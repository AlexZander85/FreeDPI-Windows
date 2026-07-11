# Patch blueprint 0005 — forced strategy smoke and probe ID mapping

Forced strategy is allowed only for smoke/deep tests. It is forbidden in AutoTune causal tests.

## Existing production route

`POST /api/v1/strategies/tune` currently accepts numeric `strategy_id` and params. The testlab uses this as the initial force/tune mechanism.

## Required improvement

Return enough runtime proof after applying a force/tune:

```json
{
  "tuned": true,
  "strategy_id": 15,
  "profile_name": "outbound_tls_tlsfrag",
  "runtime_generation": 43,
  "selected_by": "api_force"
}
```

If `strategy_id` does not map to any live profile, return a 400 with:

```json
{"error":"unmapped_strategy_id","strategy_id":35}
```

## AutoTune guard

Decision log events must include `selected_by`. AutoTune causal tests fail if candidate/promotion is `api_force`, `runner`, or anything other than `app`.
