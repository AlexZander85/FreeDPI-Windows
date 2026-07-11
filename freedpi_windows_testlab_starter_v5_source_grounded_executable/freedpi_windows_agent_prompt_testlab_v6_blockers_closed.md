# Execution prompt — FreeDPI-Windows test lab v4 source-grounded QA/API merge

You are implementing and running the FreeDPI-Windows automated test lab. Use `freedpi_windows_testlab_starter_v4_source_grounded_qaapi/` as the starter kit.

## Read first

1. `docs/architecture_mapping.md` — source-grounded architecture inventory.
2. `docs/known_limitations.md` — real gaps vs. original assumptions.
3. `docs/testlab_role_boundary.md` — the test lab is observer/orchestrator/oracle provider, not the AutoTune brain.
4. `docs/windows_test_control_contract.md` — minimal QA observer API and SCM boundaries.
5. `docs/strategy_inventory_contract.md` — reconciliation across live profiles, probe numeric IDs and dead StrategyRegistry.
6. `docs/autotune_causal_chain_contract.md` — observer-only AutoTune validation.
7. `docs/api_auth_release_risk.md` — empty API key release bug.
8. `patches/0001-qa-feature-and-routes.md` — concrete starting point for `qa` feature/routes. Reconcile it with the contract before applying.

## Non-negotiable rules

- Re-verify every architecture claim against current source before editing.
- Do not invent a single strategy ID scheme. Reconcile live profile names, numeric probe strategy IDs, and the dead trait registry separately.
- AutoTune causal tests must run the app in AUTO mode. The runner must not choose/apply the final strategy.
- Forced strategy mode is only for strategy smoke/deep tests.
- Service lifecycle must use Windows SCM/PowerShell, not `/qa/start` or `/qa/stop`.
- `/qa/*` is observer/debug only and must be compiled out of release builds.
- Do not weaken API auth for tests.
- No raw PCAP/ETW/domains/IPs leave the machine without `--allow-raw-capture`.
- Unsupported must be reported with a reason, never silently skipped.

## Priority backlog

1. Fix release auth risk first: installed config must not contain `api_key = ""`; no-header request must not authenticate; release verifier must fail if it does.
2. Add the non-default `qa` Cargo feature and minimal observer routes in `src/api/src/lib.rs`.
3. Add missing core reset/telemetry methods in `ProcessingPipeline` only where real state can be reset safely. If a reset is impossible, return unsupported sub-reset explicitly.
4. Implement `/qa/strategy_inventory` as reconciliation, not a flat list.
5. Implement `/qa/runtime_strategy_snapshot`, `/qa/flow_telemetry`, `/qa/autotune_state`, `/qa/autotune_decision_log`, `/qa/windivert_stats` from real internal state.
6. Use `tools/synthetic_dpi_server.py` for deterministic block symptoms; finish HTTP2/ICMP limitations only if platform capabilities allow.
7. Implement `tools/trafficgen_client.py` for deterministic HTTP/HTTPS/DNS/QUIC-like UDP scenarios.
8. Wire `windows_testlab_runner.py` commands to real tools without pretending stubs pass.
9. Keep named pipe out of test coverage until it is actually implemented and started by service.
10. Run release verification against real release artifacts.

## QA API response convention

Current production handlers return flat JSON. Implement `/qa/*` flat JSON unless the entire API is migrated consistently. Tools may accept envelope JSON during transition, but do not force a new envelope convention onto only `/qa/*`.

## Completion criteria

You are not done until:

- `cargo test --workspace` passes on Windows;
- service install/start/stop/restart/uninstall passes through SCM;
- strategy inventory reconciliation has no fail-severity findings or each is explicitly triaged;
- all live profiles pass smoke or are explicitly unsupported;
- DPI Probe oracle matrix passes with a confusion matrix;
- AutoTune causal-chain tests pass in AUTO mode without external strategy intervention;
- restart stress shows no orphaned process/driver state;
- privacy redaction is on by default;
- release verification passes and proves QA endpoints/test keys are not shipped;
- provider AUTO-mode report is separate and never forces strategies externally.

## Environment statement

This starter kit was produced without a Windows machine, Administrator privileges or WinDivert. Static/source reading is not a substitute for Level 1 Windows verification.


## v5 update — remaining gaps closed in starter kit

The previous backlog item "trafficgen_client.py, remaining docs/*_contract.md, and binding QA methods to real ProcessingPipeline fields" has been closed in the starter kit as scaffold/contracts:

- `tools/trafficgen_client.py` now implements HTTP/TCP/TLS/DNS/QUIC-like UDP scenarios and JSON output.
- `docs/qa_core_binding_contract.md` maps QA methods to current `ProcessingPipeline`, `PacketEngine`, `StrategyProfileRegistry`, `AutoTune`, and `ServiceEngine` fields/methods.
- `patches/0002-core-qa-bindings-and-reset-hooks.md` gives concrete Rust binding code and explicitly marks reset hooks that are missing in core.
- `contracts/qa_api.openapi.yaml` was reduced to the minimal observer/debug QA API and uses repo-style flat JSON.

Implementation priority now:

1. Fix release auth risk (`api_key = ""` in deploy/config + auth middleware missing-header comparison).
2. Add `qa` feature and minimal observer routes.
3. Add core QA snapshot methods from patch 0002.
4. Add real reset hooks only where safe; return unsupported for the rest.
5. Add decision log instrumentation at real strategy/probe/autotune decision points.
6. Run trafficgen + synthetic DPI + observer-only causal checks on Windows/Admin.


## v6 blocker-closure additions

This v6 starter kit closes the previously listed blockers as far as a testlab can, and provides app-side patch blueprints for the rest. Read these files before changing code:

1. `docs/blocker_closure_matrix.md` — exact status of each blocker.
2. `docs/strategy_inventory_contract.md` — inventory is reconciliation, not a flat list.
3. `docs/runtime_strategy_snapshot_contract.md` — required runtime proof of active profile/strategy generation.
4. `docs/flow_telemetry_contract.md` — required proof that FreeDPI observed a flow.
5. `docs/unsupported_reasons_contract.md` — reason codes for unsupported/unreachable items.
6. `patches/0003-qa-strategy-inventory-runtime-contract.md`.
7. `patches/0004-runtime-strategy-snapshot-and-flow-telemetry.md`.
8. `patches/0005-forced-strategy-and-probe-id-mapping.md`.
9. `patches/0006-release-guard-and-windows-env.md`.

New tools you must wire into the real Windows run:

- `tools/strategy_inventory_reconcile.py`
- `tools/probe_mapping_audit.py`
- `tools/flow_telemetry_probe.py`
- `tools/forced_strategy_smoke.py`
- `tools/unsupported_reason_linter.py`
- enhanced `tools/win_env_probe.py`

Non-negotiable: AutoTune causal tests remain observer-only. `forced_strategy_smoke.py` is allowed only for strategy smoke/deep tests and must never be used to prove AutoTune quality.
