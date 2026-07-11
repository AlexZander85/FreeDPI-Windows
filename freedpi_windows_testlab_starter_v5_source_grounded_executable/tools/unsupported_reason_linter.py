#!/usr/bin/env python3
"""Validate that unsupported/unreachable inventory items carry explicit reasons."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

STATUSES={'unsupported','unreachable','dead_registry_unreachable','unresolved'}

def load_json(path): return json.loads(Path(path).read_text(encoding='utf-8'))

def walk(obj, path='$'):
    if isinstance(obj, dict):
        yield path,obj
        for k,v in obj.items(): yield from walk(v, path+'.'+str(k))
    elif isinstance(obj, list):
        for i,v in enumerate(obj): yield from walk(v, f'{path}[{i}]')

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('json_file'); ap.add_argument('--out',default='')
    a=ap.parse_args(); data=load_json(a.json_file)
    findings=[]
    for p,d in walk(data):
        if not isinstance(d,dict): continue
        status=str(d.get('status') or d.get('runtime_status') or '')
        needs = status in STATUSES or d.get('ok') is False
        if needs and not d.get('unsupported_reasons') and not d.get('reason'):
            findings.append({'path':p,'status':status,'message':'missing unsupported_reasons/reason'})
    out={'ok':not findings,'findings':findings,'checked_file':a.json_file}
    if a.out: Path(a.out).write_text(json.dumps(out,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps({'ok':out['ok'],'findings':len(findings)},indent=2))
    return 0 if not findings else 1
if __name__=='__main__': raise SystemExit(main())
