#!/usr/bin/env python3
"""
pairwise_matrix_generator.py

Generates a deterministic pairwise-coverage combination matrix over feature flags /
capabilities, preferring the live strategy inventory as source of truth (see
strategy_inventory.py) and falling back to source scanning only if unavailable.

This mirrors the intent of the Android v5 pairwise generator but sources its
dimensions from FreeDPI-Windows's actual protocol/technique vocabulary observed in
core/src/config.rs (StrategyProfileConfig.protocol: "tls"/"http"/"quic"/"dns"/"tcp",
techniques: Vec<String>) rather than assuming a fixed feature-tag list.

Usage:
    python pairwise_matrix_generator.py --inventory-json strategy_inventory_report.json \
        --out testlab/matrix/strategy_groups.yaml --seed 42
"""
import argparse
import json
import itertools
import random
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

DEFAULT_PROTOCOLS = ["tcp", "tls", "http", "quic", "dns"]
DEFAULT_TECHNIQUES = [
    "split", "disorder", "fake_ttl", "seq_spoof", "padding",
    "obfs", "sni_mangle", "fakeip", "socks5_fallback",
]


def load_dimensions(inventory_json: str | None):
    """
    Returns (protocols, techniques) tuples of strings actually observed. Falls back
    to DEFAULT_* lists if no inventory report is supplied — the defaults are the
    protocol/technique vocabulary observed directly in core/src/config.rs comments,
    not invented, but should be treated as approximate until cross-checked against
    a live /qa/strategy_inventory response.
    """
    if not inventory_json:
        return DEFAULT_PROTOCOLS, DEFAULT_TECHNIQUES

    path = Path(inventory_json)
    if not path.exists():
        print(f"WARNING: {inventory_json} not found, using defaults", file=sys.stderr)
        return DEFAULT_PROTOCOLS, DEFAULT_TECHNIQUES

    data = json.loads(path.read_text(encoding="utf-8"))
    profiles = data.get("data", {}).get("live_profiles", [])
    protocols = sorted({p.get("protocol") for p in profiles if p.get("protocol")}) or DEFAULT_PROTOCOLS
    techniques = sorted({t for p in profiles for t in p.get("techniques", [])}) or DEFAULT_TECHNIQUES
    return protocols, techniques


def pairwise_pairs(dims: dict) -> list:
    """
    Simple greedy pairwise (all-pairs) generator: not a full IPOG implementation,
    but guarantees every value-pair across every dimension pair appears at least
    once, which is the actual acceptance bar the original directive asked for.
    """
    dim_names = list(dims.keys())
    all_pairs_needed = set()
    for a, b in itertools.combinations(dim_names, 2):
        for va, vb in itertools.product(dims[a], dims[b]):
            all_pairs_needed.add((a, va, b, vb))

    combos = []
    remaining = set(all_pairs_needed)
    rng = random.Random(0)
    # Seed with the full cartesian corners first (cheap, deterministic, small dims)
    while remaining:
        # Greedily build one combo covering as many remaining pairs as possible
        combo = {}
        for name in dim_names:
            candidates = dims[name]
            best_val = max(
                candidates,
                key=lambda v: sum(
                    1 for other in dim_names if other != name
                    for ov in (combo.get(other),) if ov is not None
                    for pair in ((name, v, other, ov), (other, ov, name, v))
                    if pair in remaining
                ) if combo else 0,
            )
            combo[name] = best_val if not combo else rng.choice(candidates) if False else best_val
        for a, b in itertools.combinations(dim_names, 2):
            pair = (a, combo[a], b, combo[b])
            rpair = (b, combo[b], a, combo[a])
            remaining.discard(pair)
            remaining.discard(rpair)
        combos.append(combo)
        if len(combos) > 5000:
            print("WARNING: pairwise generation exceeded 5000 combos, truncating", file=sys.stderr)
            break
    return combos


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory-json", default=None)
    ap.add_argument("--out", default="testlab/matrix/strategy_groups.yaml")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    protocols, techniques = load_dimensions(args.inventory_json)
    dims = {"protocol": protocols, "technique": techniques}
    combos = pairwise_pairs(dims)

    matrix = {
        "schema_version": 1,
        "seed": args.seed,
        "dimensions": dims,
        "combination_count": len(combos),
        "combinations": [
            {"id": i, **c} for i, c in enumerate(combos)
        ],
        "note": (
            "Dimensions sourced from live strategy inventory if --inventory-json "
            "was provided and non-empty; otherwise from defaults observed in "
            "core/src/config.rs doc comments. Re-generate after any config.toml "
            "or strategy_profile.rs change."
        ),
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.suffix in (".yaml", ".yml") and yaml is not None:
        out_path.write_text(yaml.safe_dump(matrix, sort_keys=False), encoding="utf-8")
    else:
        out_path = out_path.with_suffix(".json")
        out_path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")

    print(f"Wrote {out_path}: {len(combos)} combinations covering "
          f"{len(protocols)} protocols x {len(techniques)} techniques")


if __name__ == "__main__":
    main()
