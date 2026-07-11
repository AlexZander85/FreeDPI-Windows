# Patch blueprint 0003 — `/qa/strategy_inventory` reconciliation endpoint

Goal: expose the same reconciliation model as `tools/strategy_inventory_reconcile.py`, but from the live app.

## Required app-side changes

### core/src/adaptive/strategy_profile.rs

Add a QA-only serializable snapshot method:

```rust
#[cfg(feature = "qa")]
#[derive(Debug, Clone, serde::Serialize)]
pub struct StrategyProfileSnapshot {
    pub name: String,
    pub strategy_id: u32,
    pub category: String,
    pub techniques: Vec<String>,
    pub source: String,
    pub runtime_status: String,
    pub force_selectable: bool,
    pub auto_selectable: bool,
    pub unsupported_reasons: Vec<String>,
}

#[cfg(feature = "qa")]
impl StrategyProfileRegistry {
    pub fn qa_profiles_snapshot(&self) -> Vec<StrategyProfileSnapshot> {
        self.profiles.values().map(|p| StrategyProfileSnapshot {
            name: p.name.clone(),
            strategy_id: p.strategy_id,
            category: format!("{:?}", p.category),
            techniques: p.techniques.iter().map(|t| format!("{:?}", t)).collect(),
            source: "builtin_or_config".to_string(),
            runtime_status: "live".to_string(),
            force_selectable: true,
            auto_selectable: true,
            unsupported_reasons: vec![],
        }).collect()
    }
}
```

If `profiles` is private, implement inside the module rather than exposing the map.

### probe numeric mapping

Expose a QA-only static list of numeric strategy IDs used by `probe/strategy_map.rs`. Prefer implementing this in the probe module itself rather than duplicating literals in API.

```rust
#[cfg(feature = "qa")]
pub fn qa_probe_strategy_ids() -> Vec<u32> { vec![1,3,4,6,7,8,9,15,35,50,60,61,70,100] }
```

If these IDs change, this helper must be updated with the same source of truth as `recommend()`.

### api/src/lib.rs

`GET /qa/strategy_inventory` returns flat JSON with:

- `ok: true`
- `source: "runtime"`
- `live_profiles`
- `probe_numeric_ids` mapped/unresolved using `StrategyProfileRegistry::get_by_id`
- `dead_registry_entries` with `StrategyRegistry` status if it remains uncalled from runtime
- `reconciliation`

Do not claim dead `StrategyRegistry` entries are live until traffic-path call sites exist.
