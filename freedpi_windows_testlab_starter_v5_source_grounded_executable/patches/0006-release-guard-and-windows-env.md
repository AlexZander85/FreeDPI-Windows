# Patch blueprint 0006 — release guard and Windows environment validation

## Release guard

Fix the default install path:

- `dist/deploy.ps1` must not write `api_key = ""`.
- Either omit the field so serde default generation fires, or generate a strong random key during install.
- `auth_middleware` must reject empty configured API keys in release builds.
- Release verification must fail if `/qa/*` routes are reachable or route strings are embedded in the binary.

## Windows/Admin/WinDivert environment

The testlab can probe capabilities but cannot fake real packet-path validation.

- Level 0: no admin, no WinDivert; static/source/cargo tests only.
- Level 1: Windows + Administrator + WinDivert; service and synthetic traffic.
- Level 2: real provider AUTO mode.

`tools/win_env_probe.py` and `scripts/env_check.ps1` report capability, not pass/fail of packet interception.
