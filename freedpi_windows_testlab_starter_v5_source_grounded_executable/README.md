# FreeDPI Windows Test Lab Starter v4 — observer/source-grounded/QA-API merge

This package merges two strands of work:

1. the broad v3 observer scaffold: role boundary, QA templates, OpenAPI contract, synthetic DPI / traffic / privacy / release tooling, and Windows-oriented scripts;
2. the implementation agent's source-grounded findings and working tools: real architecture mapping, strategy inventory reconciliation, concrete `/qa` feature patch sketch, synthetic DPI server, release verifier, and SCM-oriented scripts.

## Core rule

The lab is an observer/orchestrator/oracle provider. It must not become the strategy brain.

- Forced strategies are allowed only for forced-strategy smoke/deep verification.
- DPI Probe tests create known local symptoms and verify the app's own classification.
- AutoTune tests run the app in AUTO mode and verify the app's own candidate/canary/promote/rollback causal chain.
- Service lifecycle is tested via Windows SCM, not `/qa/start` or `/qa/stop`.

## Most important source-grounded findings

- `StrategyRegistry` in `core/src/adaptive/strategy.rs` is currently dead from the traffic path; live profiles come from `StrategyProfileRegistry` in `adaptive/strategy_profile.rs`.
- Probe recommendations use a third numeric `strategy_id: u32` space that must be reconciled with live profile names.
- There is no live named pipe control channel today. `PipeServer::run()` is a stub and is not started by the service.
- Existing API routes are `/api/v1/*`; `/qa/*` does not exist yet and must be added behind a non-default `qa` feature.
- QA API should be observer/debug surface only, and should not duplicate production routes or SCM lifecycle.
- `dist/deploy.ps1` writes `api_key = ""`, which can open the API with no `X-API-Key` if not fixed.

## Files to read first

1. `docs/architecture_mapping.md`
2. `docs/known_limitations.md`
3. `docs/testlab_role_boundary.md`
4. `docs/windows_test_control_contract.md`
5. `docs/strategy_inventory_contract.md`
6. `docs/autotune_causal_chain_contract.md`
7. `docs/api_auth_release_risk.md`
8. `patches/0001-qa-feature-and-routes.md`

## Useful commands

Source fallback inventory:

```powershell
python tools/strategy_inventory.py --source-fallback --repo-path C:\path\to\FreeDPI-Windows-master --out runs\inventory\strategy_inventory
```

Release verification:

```powershell
python tools/release_verify.py --config "C:\Program Files\FreeDPI\config.toml" --binary "C:\Program Files\FreeDPI\freedpi-service.exe" --base-url http://127.0.0.1:11337 --api-key $env:FREEDPI_API_KEY
```

Synthetic DPI server:

```powershell
python tools/synthetic_dpi_server.py --mode TLS_HANDSHAKE_TIMEOUT --tcp-port 18443 --http-port 18080 --dns-port 10053
```

QA contract check, after implementing `/qa/*`:

```powershell
python tools/qa_contract_check.py --base http://127.0.0.1:11337 --api-key $env:FREEDPI_API_KEY --json-out runs\qa_contract.json
```

## Execution levels

- Level 0: source inventory, cargo tests, replay/fuzz-lite, no WinDivert/Admin.
- Level 1: local Windows Administrator + WinDivert + service + synthetic DPI.
- Level 2: real provider AUTO-mode validation, never forcing strategies externally.

## Environment limitation

This package was assembled without executing Windows SCM/WinDivert tests. Python tools were syntax-checked in this environment. All Windows packet/service behavior must be verified on Windows 10/11 with Administrator privileges.


## v5 source-grounded executable closure

This version closes the remaining items called out by the implementation agent:

- `tools/trafficgen_client.py` is implemented for deterministic HTTP/TCP/TLS/DNS/QUIC-like UDP traffic generation.
- `docs/qa_core_binding_contract.md` maps QA endpoints to real `ProcessingPipeline` and `PacketEngine` fields/methods in the reviewed source snapshot.
- `patches/0002-core-qa-bindings-and-reset-hooks.md` provides concrete Rust snapshot bindings and documents which reset hooks are missing in core.
- Remaining contract docs were expanded to distinguish client-side traffic evidence from internal FreeDPI telemetry.

The kit is still observer-only: it does not select strategies for AutoTune tests.


## v6 blocker-closure additions

This package adds runnable tools and app-side patch blueprints for the remaining blockers:

- strategy inventory reconciliation;
- runtime strategy snapshot contract;
- flow telemetry proof;
- forced strategy smoke runner;
- probe numeric ID mapping audit;
- unsupported-reason linter;
- release guard and Windows/Admin/WinDivert capability probe.

Run examples:

```powershell
python tools/strategy_inventory_reconcile.py --repo-root .. --out runs/strategy_inventory_reconcile.json
python tools/probe_mapping_audit.py --repo-root .. --out runs/probe_mapping_audit.json
python tools/unsupported_reason_linter.py runs/strategy_inventory_reconcile.json
python tools/win_env_probe.py
python tools/windows_testlab_runner.py flow-telemetry-probe --api-base http://127.0.0.1:11337
python tools/windows_testlab_runner.py all-strategies-smoke --api-base http://127.0.0.1:11337 --limit 10
```

If `/qa/*` hooks are absent, tools report `unsupported`, not `pass`.
