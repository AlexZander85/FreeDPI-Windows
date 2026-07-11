# Patch blueprint 0004 — runtime strategy snapshot and flow telemetry

Goal: make strategy smoke and AutoTune causal tests provable.

## `/qa/runtime_strategy_snapshot`

Add a QA-only method on `ProcessingPipeline`:

```rust
#[cfg(feature = "qa")]
pub fn qa_runtime_strategy_snapshot_json(&self) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "source": "pipeline",
        "generation": self.qa_strategy_generation(),
        "active_profiles": {
            "tls": { "name": self.active_profile_tls.load().as_ref(), "selected_by": "config" },
            "quic": { "name": self.active_profile_quic.load().as_ref(), "selected_by": "config" },
            "http": { "name": self.active_profile_http.load().as_ref(), "selected_by": "config" }
        },
        "unsupported": []
    })
}
```

The exact fields must be adjusted to the current code. If active profile storage changes to `ProfileId`, expose both `profile_id` and `name`.

## `/qa/flow_telemetry`

Minimum first implementation may be aggregate-only:

```rust
#[cfg(feature = "qa")]
pub fn qa_flow_telemetry_json(&self) -> serde_json::Value {
    let s = self.stats.snapshot();
    let p = self.packet_engine().stats_snapshot();
    serde_json::json!({
        "ok": true,
        "generation": 0,
        "aggregate": {
            "flows_observed": 0,
            "packets_received": p.packets_received,
            "packets_forwarded": s.forwarded,
            "packets_injected": p.packets_injected,
            "packets_dropped": p.packets_dropped,
            "tls_outbound": s.tls_outbound,
            "fake_ch_injected": s.fake_ch_injected
        },
        "flows": [],
        "unsupported": ["per_flow_ring_buffer_missing"]
    })
}
```

Deep tests require a per-flow ring buffer later. The aggregate-only version is still useful because `tools/flow_telemetry_probe.py` can prove counters change after traffic.
