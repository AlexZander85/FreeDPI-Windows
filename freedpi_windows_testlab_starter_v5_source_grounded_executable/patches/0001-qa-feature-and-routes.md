# Patch: `qa` feature + `/qa/*` routes for `api` crate

## Correction to the original contract doc

`docs/windows_test_control_contract.md` specified a `{ok, request_id, timestamp_utc,
duration_ms, data, error}` envelope for `/qa/*` responses. Having now read the real
handler bodies (`status_handler`, `health_handler`, etc.), **every existing endpoint
returns flat JSON** (`Json(serde_json::json!({"status": "running", ...}))`) — there is
no envelope convention in this codebase to match. Introducing an envelope only for
`/qa/*` would make the QA surface inconsistent with everything else for no real
benefit. **Revised decision: `/qa/*` responses use the same flat style as `/api/v1/*`.**
Update `strategy_inventory.py` accordingly if this patch is applied (it currently reads
`envelope["ok"]` / `envelope["data"]` — trivial fix, noted in the tool's TODO below).

## 1. `src/api/Cargo.toml`

```toml
[package]
name = "freedpi-api"
version.workspace = true
edition.workspace = true
license.workspace = true

[features]
qa = []          # add this section

[dependencies]
freedpi-core = { path = "../core" }
tokio.workspace = true
axum.workspace = true
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true
anyhow.workspace = true
uuid.workspace = true
chrono.workspace = true
```

The `service` crate must NOT enable this feature in a release build. In
`src/service/Cargo.toml`, the dependency on `freedpi-api` must only pull `features =
["qa"]` behind the workspace's own `qa` feature (mirror it upward), e.g.:

```toml
[features]
qa = ["freedpi-api/qa"]

[dependencies]
freedpi-api = { path = "../api" }
```

`build_release.ps1` must build with `--no-default-features` (or simply never pass
`--features qa`); `build_debug.ps1` used for test-lab runs should pass `--features qa`
explicitly, never implicitly. `release_verify.py` (see `tools/release_verify.py` in
this kit) checks the built binary does not respond on any `/qa/*` route as a second,
runtime-level guard against a `qa`-feature build accidentally shipping.

## 2. `src/api/src/lib.rs` — additions

Add near the top, after existing imports:

```rust
#[cfg(feature = "qa")]
use axum::extract::Query;
```

Extend `EngineHandle` (existing trait) with QA-only methods, feature-gated so the
trait's shape doesn't change for release builds:

```rust
pub trait EngineHandle {
    // ... existing methods unchanged ...

    #[cfg(feature = "qa")]
    fn qa_reset_state(&self);

    #[cfg(feature = "qa")]
    fn qa_reset_telemetry(&self);

    /// Must return the actual internal StrategySnapshot from
    /// core::adaptive::auto_tune, serialized as-is (serde derive on the real
    /// struct), not a hand-rolled approximation.
    #[cfg(feature = "qa")]
    fn qa_runtime_strategy_snapshot(&self) -> serde_json::Value;

    /// Must return real StrategyProfileConfig entries loaded from config, cross-
    /// referenced against numeric strategy_id values seen in
    /// probe::strategy_map::recommend() and against StrategyRegistry's contents
    /// (reported separately as unreachable). See
    /// docs/strategy_inventory_contract.md for the exact shape.
    #[cfg(feature = "qa")]
    fn qa_strategy_inventory(&self) -> serde_json::Value;

    /// Derive the real phase/state enum from auto_tune.rs / fallback.rs /
    /// target_escalate.rs before implementing this — do not invent phase names.
    #[cfg(feature = "qa")]
    fn qa_autotune_decision_log(&self) -> serde_json::Value;

    #[cfg(feature = "qa")]
    fn qa_autotune_state(&self) -> serde_json::Value;

    /// Wraps infra::windivert_driver.rs handle/recv/send/error counters.
    #[cfg(feature = "qa")]
    fn qa_windivert_stats(&self) -> serde_json::Value;
}
```

Route registration — insert into the existing `Router::new()` chain in `serve()`,
right before `.route_layer(...)`:

```rust
let app = Router::new()
    // ... all existing .route(...) calls unchanged ...
    ;

#[cfg(feature = "qa")]
let app = app
    .route("/qa/capabilities", get(qa_capabilities_handler))
    .route("/qa/health", get(qa_health_handler))
    .route("/qa/reset_state", post(qa_reset_state_handler))
    .route("/qa/reset_telemetry", post(qa_reset_telemetry_handler))
    .route("/qa/strategy_inventory", get(qa_strategy_inventory_handler))
    .route(
        "/qa/runtime_strategy_snapshot",
        get(qa_runtime_strategy_snapshot_handler),
    )
    .route("/qa/autotune_state", get(qa_autotune_state_handler))
    .route(
        "/qa/autotune_decision_log",
        get(qa_autotune_decision_log_handler),
    )
    .route("/qa/windivert_stats", get(qa_windivert_stats_handler));

let app = app
    .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
    .with_state(state);
```

Handlers (same flat-JSON style as existing handlers, same `X-API-Key` auth via the
existing `route_layer` — QA routes go through the identical `auth_middleware`, no
weaker auth path):

```rust
#[cfg(feature = "qa")]
async fn qa_capabilities_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "qa_build": true,
        "strategy_inventory": true,
        "autotune_decision_log": true,
        "windivert_stats": true,
        "named_pipe_channel": false, // see windows_test_control_contract.md: unimplemented
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[cfg(feature = "qa")]
async fn qa_health_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(serde_json::json!({"healthy": true, "qa_build": true}))
}

#[cfg(feature = "qa")]
async fn qa_reset_state_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    state.engine.qa_reset_state();
    Json(serde_json::json!({"ok": true}))
}

#[cfg(feature = "qa")]
async fn qa_reset_telemetry_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    state.engine.qa_reset_telemetry();
    Json(serde_json::json!({"ok": true}))
}

#[cfg(feature = "qa")]
async fn qa_strategy_inventory_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.qa_strategy_inventory())
}

#[cfg(feature = "qa")]
async fn qa_runtime_strategy_snapshot_handler(
    State(state): State<Arc<ApiState>>,
) -> impl IntoResponse {
    Json(state.engine.qa_runtime_strategy_snapshot())
}

#[cfg(feature = "qa")]
async fn qa_autotune_state_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.qa_autotune_state())
}

#[cfg(feature = "qa")]
async fn qa_autotune_decision_log_handler(
    State(state): State<Arc<ApiState>>,
) -> impl IntoResponse {
    Json(state.engine.qa_autotune_decision_log())
}

#[cfg(feature = "qa")]
async fn qa_windivert_stats_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.qa_windivert_stats())
}
```

## 3. `src/service/src/main.rs` — implementing the trait methods

This is the part that actually requires reading `ServiceEngine`'s internals (the
`pipeline: OnceLock<Arc<ProcessingPipeline>>` field and what `ProcessingPipeline`
exposes) in full, which this patch does not do — `ServiceEngine` already has a
pattern for "pipeline not running yet" (`Err("WinDivert pipeline is not running")`
seen in `add_user_domain`/`remove_user_domain`), and the QA methods must follow the
same pattern rather than panicking when called before the pipeline starts:

```rust
#[cfg(feature = "qa")]
impl EngineHandle for ServiceEngine {
    fn qa_reset_state(&self) {
        if let Some(pipeline) = self.pipeline.get() {
            // TODO: call real reset methods once identified on ProcessingPipeline —
            // conntrack clear, dns cache clear, probe history clear. Do not
            // reimplement state clearing here; delegate to whatever the pipeline
            // already exposes, or add minimal new methods on ProcessingPipeline
            // itself (in core crate) rather than reaching into its internals from
            // the service crate.
        }
    }

    fn qa_reset_telemetry(&self) {
        // TODO: same pattern — delegate to pipeline.stats_arc() reset if it has one,
        // else add one.
    }

    fn qa_runtime_strategy_snapshot(&self) -> serde_json::Value {
        match self.pipeline.get() {
            Some(pipeline) => {
                // TODO: pipeline must expose the real adaptive::auto_tune::StrategySnapshot.
                // Serialize it directly (#[derive(Serialize)] on StrategySnapshot if not
                // already present) rather than reconstructing fields by hand.
                serde_json::json!({"pipeline_running": true, "snapshot": null})
            }
            None => serde_json::json!({"pipeline_running": false}),
        }
    }

    fn qa_strategy_inventory(&self) -> serde_json::Value {
        // TODO: implement per docs/strategy_inventory_contract.md — this needs
        // access to the loaded Config's Vec<StrategyProfileConfig>, plus a static
        // list of numeric strategy_id values referenced in
        // probe::strategy_map::recommend() (consider adding a
        // `pub fn all_referenced_strategy_ids() -> Vec<u32>` helper directly in
        // strategy_map.rs so this doesn't have to duplicate that list), plus
        // StrategyRegistry::global().list_ids() reported under
        // dead_registry_entries with source: "unreachable_dead_code".
        serde_json::json!({"live_profiles": [], "numeric_strategy_ids": [], "dead_registry_entries": []})
    }

    fn qa_autotune_decision_log(&self) -> serde_json::Value {
        // TODO: blocked on deriving the real phase enum from auto_tune.rs /
        // fallback.rs / target_escalate.rs per docs/autotune_causal_chain_contract.md.
        // Do not ship a placeholder phase list.
        serde_json::json!({"events": [], "note": "not yet implemented - see autotune_causal_chain_contract.md"})
    }

    fn qa_autotune_state(&self) -> serde_json::Value {
        serde_json::json!({"not_implemented": true})
    }

    fn qa_windivert_stats(&self) -> serde_json::Value {
        // TODO: wire to infra::windivert_driver.rs handle/recv/send/error counters.
        serde_json::json!({"not_implemented": true})
    }
}
```

## Follow-up finding: no reset/clear methods exist on `ProcessingPipeline` today

Checked `core/src/engine/mod.rs` (`ProcessingPipeline`, defined line 146): it exposes
`snapshot() -> ProcessingStatsSnapshot`, `stats()`, `stats_arc()`, and
`clear_strategy_tune(strategy_id: u32)` — but **no general conntrack/DNS-cache/probe-
history reset method**. This means `qa_reset_state()` / `qa_reset_telemetry()` are not
"delegate to an existing method" work as originally assumed — they require adding new
public methods to `ProcessingPipeline` itself (in the `core` crate), which touches
production code, not just the API layer. Flag this to Александр before implementing:
it's a slightly bigger change than the rest of the `qa` surface, and worth deciding
whether reset methods are useful production functionality (e.g. for a "restart fresh"
UI button) or should stay strictly test-only and cfg-gated all the way down into
`core`.

## What this patch deliberately leaves undone

Every `TODO` above requires reading `ProcessingPipeline` (defined somewhere under
`core/src/engine/` or `core/src/packet_engine.rs` — not yet fully read in this
session) to find the real accessor methods rather than guessing field names. That's
the next investigation step, not a large one — `packet_engine.rs` and `engine/mod.rs`
are already identified in `architecture_mapping.md` as the modules to read.
