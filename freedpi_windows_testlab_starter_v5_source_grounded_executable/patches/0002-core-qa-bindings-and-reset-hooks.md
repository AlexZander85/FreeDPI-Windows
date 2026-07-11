# Patch: core QA binding methods and reset hooks

This patch complements `0001-qa-feature-and-routes.md`. It is source-grounded in current `ProcessingPipeline` / `PacketEngine` APIs.

## 1. Add serializable snapshots

`adaptive/auto_tune.rs`:

```rust
#[derive(Debug, Clone, serde::Serialize)]
pub struct StrategySnapshot {
    pub success_count: u64,
    pub fail_count: u64,
    pub avg_latency_us: u64,
}
```

## 2. Add `StrategyProfileRegistry` snapshot API

Do not expose the private `profiles` map directly. Add a serializable snapshot type that omits `desync_group`:

```rust
#[cfg(feature = "qa")]
#[derive(Debug, Clone, serde::Serialize)]
pub struct StrategyProfileSnapshot {
    pub name: String,
    pub category: String,
    pub techniques: Vec<String>,
    pub default_params: crate::adaptive::auto_tune::TuneParams,
    pub description: String,
    pub strategy_id: u32,
}

#[cfg(feature = "qa")]
impl StrategyProfileRegistry {
    pub fn profiles_snapshot(&self) -> Vec<StrategyProfileSnapshot> {
        self.profiles.values().map(|p| StrategyProfileSnapshot {
            name: p.name.clone(),
            category: format!("{:?}", p.category),
            techniques: p.techniques.iter().map(|t| format!("{:?}", t)).collect(),
            default_params: p.default_params.clone(),
            description: p.description.clone(),
            strategy_id: p.strategy_id,
        }).collect()
    }
}
```

## 3. Add `ProcessingPipeline` QA snapshots

```rust
#[cfg(feature = "qa")]
impl ProcessingPipeline {
    pub fn qa_processing_stats_json(&self) -> serde_json::Value {
        let s = self.stats.snapshot();
        serde_json::json!({
            "total_received": s.total_received,
            "injected_skipped": s.injected_skipped,
            "tls_outbound": s.tls_outbound,
            "fake_ch_injected": s.fake_ch_injected,
            "forwarded": s.forwarded,
            "dropped": s.dropped,
            "errors": s.errors
        })
    }

    pub fn qa_windivert_stats_json(&self) -> serde_json::Value {
        let p = self.packet_engine().stats_snapshot();
        serde_json::json!({
            "has_divert": self.packet_engine().has_divert(),
            "has_raw_socket": self.packet_engine().has_raw_socket(),
            "has_raw_socket_v4": self.packet_engine().has_raw_socket_v4(),
            "has_raw_socket_v6": self.packet_engine().has_raw_socket_v6(),
            "packets_received": p.packets_received,
            "packets_sent": p.packets_sent,
            "packets_injected": p.packets_injected,
            "packets_dropped": p.packets_dropped
        })
    }

    pub fn qa_runtime_strategy_snapshot_json(&self) -> serde_json::Value {
        serde_json::json!({
            "active_profiles": {
                "tls": self.active_profile_tls.load().as_ref(),
                "quic": self.active_profile_quic.load().as_ref(),
                "http": self.active_profile_http.load().as_ref()
            },
            "auto_tune_metrics": self.auto_tune.lock().unwrap().all_metrics(),
            "processing_stats": self.qa_processing_stats_json()
        })
    }

    pub fn qa_strategy_profiles_json(&self) -> serde_json::Value {
        serde_json::json!({
            "live_profiles": self.profile_registry().profiles_snapshot()
        })
    }
}
```

QA read locks are acceptable in debug endpoints. Do not use this to justify packet-path locking.

## 4. Reset hooks are not currently available

`ProcessingPipeline` currently has no general reset method. `AutoTune::reset()` clears `strategy_indices` and is unsafe as a generic telemetry reset unless registrations are rebuilt. Therefore `/qa/reset_state` and `/qa/reset_telemetry` must return partial reset results until explicit reset hooks are added.

Add reset methods deliberately later:

- `ProcessingStats::reset()`
- `PacketStats::reset()`
- `Conntrack::clear()` if needed
- `DnsProxyEngine` / `FakeIpManager` reachable reset/snapshot hooks
- DecisionLog reset

Until then, unsupported reset categories must be returned in JSON instead of silently claiming success.
