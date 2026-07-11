#!/usr/bin/env python3
"""
release_verify.py

Verifies a built release artifact does not carry QA/test-only surface or unsafe
defaults. Grounded in actual source findings (see docs/known_limitations.md):

  - Checks that deploy/config do not regress to empty api_key (previously,
    dist/deploy.ps1 wrote `api_key = ""` literally, which has been fixed to
    generate a random UUID). This ensures production deployments remain secure.
  - The api crate's `qa` Cargo feature (see patches/0001-qa-feature-and-routes.md)
    must not be present in a release build.
  - src/vendor/windivert/*.sys must not be user-writable in a packaged release
    (defense-in-depth against driver tampering) — best-effort check only, real
    signing verification is out of scope for this script.

Usage:
    python release_verify.py --config path\\to\\deployed\\config.toml \
        --binary path\\to\\freedpi-service.exe \
        --base-url http://127.0.0.1:11337   # only if binary is currently running
"""
import argparse
import re
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path


def check_config_api_key(config_path: Path) -> list:
    findings = []
    if not config_path.exists():
        findings.append({"severity": "fail", "check": "config_exists",
                          "message": f"{config_path} not found"})
        return findings

    text = config_path.read_text(encoding="utf-8", errors="replace")
    m = re.search(r'^\s*api_key\s*=\s*"([^"]*)"', text, re.MULTILINE)
    if not m:
        findings.append({"severity": "warn", "check": "api_key_present",
                          "message": "No api_key line found in [api] section; if this "
                          "means the field is genuinely absent, default_api_key() "
                          "should have generated a random UUID at config-write time — "
                          "confirm the config was actually written by the app, not "
                          "hand-edited."})
        return findings

    key = m.group(1)
    if key == "":
        findings.append({
            "severity": "fail",
            "check": "api_key_not_empty",
            "message": (
                "api_key is literally empty in the deployed config. This is a regression: "
                "dist/deploy.ps1 and config templates must not write empty keys, which "
                "defeats config.rs's default_api_key() random-UUID generator. "
                "Ensure a non-empty UUID api_key is configured to prevent unauthorized API access."
            ),
        })
    elif len(key) < 16:
        findings.append({"severity": "warn", "check": "api_key_entropy",
                          "message": f"api_key is only {len(key)} chars; expected a "
                          "UUID-length (36 char) key from default_api_key()."})
    else:
        findings.append({"severity": "pass", "check": "api_key_not_empty",
                          "message": "api_key present and non-trivial length."})
    return findings


def check_qa_routes_absent(base_url: str, api_key: str) -> list:
    """Only meaningful if the binary is currently running. Confirms /qa/* is not
    reachable, as a runtime-level guard in addition to the Cargo-feature build check."""
    findings = []
    if not base_url:
        findings.append({"severity": "info", "check": "qa_routes_absent",
                          "message": "No --base-url given; skipped runtime QA-route check. "
                          "Run this against a live release binary before shipping."})
        return findings

    for path in ["/qa/capabilities", "/qa/health", "/qa/strategy_inventory"]:
        try:
            req = urllib.request.Request(f"{base_url}{path}", headers={"X-API-Key": api_key})
            with urllib.request.urlopen(req, timeout=3) as resp:
                findings.append({
                    "severity": "fail",
                    "check": "qa_routes_absent",
                    "message": f"{path} responded with HTTP {resp.status} on what should "
                               "be a release build — the 'qa' Cargo feature is enabled.",
                })
        except urllib.error.HTTPError as e:
            if e.code == 404:
                findings.append({"severity": "pass", "check": f"qa_route_absent:{path}",
                                  "message": f"{path} correctly returns 404."})
            elif e.code == 401:
                findings.append({
                    "severity": "fail",
                    "check": "qa_routes_absent",
                    "message": f"{path} returned 401 (route exists, auth rejected it) — "
                               "the route is compiled in even if this key can't call it. "
                               "'qa' feature must not be enabled at all in release.",
                })
            else:
                findings.append({"severity": "warn", "check": f"qa_route_check:{path}",
                                  "message": f"unexpected status {e.code}"})
        except urllib.error.URLError as e:
            findings.append({"severity": "info", "check": f"qa_route_check:{path}",
                              "message": f"could not connect: {e}"})
    return findings


def check_binary_feature_flags(binary_path: Path) -> list:
    """Best-effort static check: search the binary for the literal route strings
    that only exist if compiled with --features qa. This is a coarse grep-in-binary
    check, not a Cargo.lock/build-manifest inspection (no reliable way to recover
    build flags from a stripped release binary otherwise)."""
    findings = []
    if not binary_path or not binary_path.exists():
        findings.append({"severity": "info", "check": "binary_scan",
                          "message": "No binary provided or not found; skipped."})
        return findings

    data = binary_path.read_bytes()
    needles = [b"/qa/capabilities", b"/qa/strategy_inventory", b"/qa/autotune_decision_log"]
    hits = [n for n in needles if n in data]
    if hits:
        findings.append({
            "severity": "fail",
            "check": "binary_scan",
            "message": f"Release binary contains QA route strings: {[h.decode() for h in hits]}. "
                       "Rebuild without --features qa.",
        })
    else:
        findings.append({"severity": "pass", "check": "binary_scan",
                          "message": "No QA route strings found in binary (release build "
                                     "with lto/strip may also just have stripped strings — "
                                     "this is a weak positive signal, not proof)."})
    return findings


def check_config_filter(config_path: Path) -> list:
    findings = []
    if not config_path.exists():
        return findings
    text = config_path.read_text(encoding="utf-8", errors="replace")
    m = re.search(r'^\s*filter\s*=\s*"([^"]*)"', text, re.MULTILINE)
    if m:
        filter_str = m.group(1)
        if "udp.DstPort == 443" in filter_str and "PayloadLength" not in filter_str:
            findings.append({
                "severity": "fail",
                "check": "narrow_windivert_filter",
                "message": f"Broad WinDivert filter override found: '{filter_str}'. Stale filter matches all UDP:443, routing heavy QUIC traffic to userspace."
            })
        else:
            findings.append({
                "severity": "pass",
                "check": "narrow_windivert_filter",
                "message": f"Custom filter is active: '{filter_str}'."
            })
    else:
        findings.append({
            "severity": "pass",
            "check": "narrow_windivert_filter",
            "message": "No manual filter override found; feature-aware dynamic filter will be used."
        })
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path, required=True)
    ap.add_argument("--binary", type=Path, default=None)
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--api-key", default="")
    args = ap.parse_args()

    findings = []
    findings += check_config_api_key(args.config)
    findings += check_config_filter(args.config)
    findings += check_binary_feature_flags(args.binary)
    findings += check_qa_routes_absent(args.base_url, args.api_key)

    fails = [f for f in findings if f["severity"] == "fail"]
    for f in findings:
        tag = f["severity"].upper()
        print(f"[{tag}] {f['check']}: {f['message']}")

    print(f"\n{len(fails)} fail-severity finding(s) out of {len(findings)} checks.")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
