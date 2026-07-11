#!/usr/bin/env python3
"""Audit numeric probe strategy IDs against live StrategyProfileRegistry profiles."""
from __future__ import annotations
import argparse, json, subprocess, sys
from pathlib import Path

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--repo-root',default='..'); ap.add_argument('--out',default='probe_mapping_audit.json')
    a=ap.parse_args()
    tmp=Path(a.out).with_suffix('.inventory.tmp.json')
    script=Path(__file__).with_name('strategy_inventory_reconcile.py')
    p=subprocess.run([sys.executable,str(script),'--repo-root',a.repo_root,'--out',str(tmp)], text=True, capture_output=True)
    if p.returncode not in (0,1):
        print(p.stdout); print(p.stderr, file=sys.stderr); return p.returncode
    rep=json.loads(tmp.read_text(encoding='utf-8'))
    inv=rep['inventory']
    mapped=[x for x in inv.get('probe_numeric_ids',[]) if x.get('status')=='mapped']
    unresolved=[x for x in inv.get('probe_numeric_ids',[]) if x.get('status')!='mapped']
    out={'mapped_total':len(mapped),'unresolved_total':len(unresolved),'mapped':mapped,'unresolved':unresolved,'status':'pass' if not unresolved else 'warn'}
    Path(a.out).write_text(json.dumps(out,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps({'mapped':len(mapped),'unresolved':len(unresolved)},indent=2))
    return 0 if not unresolved else 1
if __name__=='__main__': raise SystemExit(main())
