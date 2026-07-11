#!/usr/bin/env python3
"""Source-grounded strategy inventory reconciler.

It prefers `/qa/strategy_inventory` when available. If not, it statically extracts:
- live StrategyProfileRegistry registrations from adaptive/strategy_profile.rs;
- numeric strategy_id recommendations from probe/strategy_map.rs;
- dead StrategyRegistry reachability from adaptive/strategy.rs call sites.

Static fallback is approximate and must be reported as `source_fallback`, never full pass.
"""
from __future__ import annotations
import argparse, json, re, sys, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime, timezone


def read(p: Path) -> str:
    return p.read_text(encoding='utf-8', errors='replace') if p.exists() else ''


def fetch(base: str, api_key: str):
    req=urllib.request.Request(base.rstrip('/') + '/qa/strategy_inventory')
    if api_key: req.add_header('X-API-Key', api_key)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read() or b'{}')
    except Exception as e:
        return {'ok': False, 'error': repr(e)}


def register_blocks(text: str):
    needle='registry.register('
    pos=0
    while True:
        i=text.find(needle,pos)
        if i<0: break
        j=i+len(needle)
        depth=1
        k=j
        in_str=False
        esc=False
        while k < len(text) and depth>0:
            ch=text[k]
            if in_str:
                if esc: esc=False
                elif ch=='\\': esc=True
                elif ch=='"': in_str=False
            else:
                if ch=='"': in_str=True
                elif ch=='(': depth += 1
                elif ch==')': depth -= 1
            k += 1
        yield text[i:k]
        pos=k


def extract_live_profiles(repo: Path):
    f=repo/'src/core/src/adaptive/strategy_profile.rs'
    text=read(f)
    out=[]
    for block in register_blocks(text):
        strings=re.findall(r'"([^"]*)"', block)
        # register(base_config, "name", StrategyCategory::X, ..., "description", id)
        name=strings[0] if strings else None
        desc=strings[-1] if len(strings)>=2 else ''
        cat_m=re.search(r'StrategyCategory::(\w+)', block)
        sid_m=re.search(r',\s*(\d+)\s*,?\s*\)\s*$', block, re.S)
        if not (name and cat_m and sid_m):
            continue
        techs=[]
        for t in re.findall(r'DesyncTechnique::(\w+)', block):
            if t not in techs: techs.append(t)
        out.append({'name':name,'strategy_id':int(sid_m.group(1)),'category':cat_m.group(1),'description':desc,'techniques':techs,'source':'builtin','runtime_status':'live','force_selectable':True,'auto_selectable':True,'unsupported_reasons':[]})
    return out


def extract_probe_ids(repo: Path):
    text=read(repo/'src/core/src/probe/strategy_map.rs')
    ids=sorted({int(x) for x in re.findall(r'strategy_id:\s*(\d+)', text)})
    return ids


def dead_registry_status(repo: Path):
    root=repo/'src'
    matches=[]
    for p in root.rglob('*.rs'):
        txt=read(p)
        if 'StrategyRegistry::global' in txt:
            matches.append(str(p.relative_to(repo)))
    # If only adaptive/strategy.rs and tests mention it, mark as not traffic-path live.
    traffic=[m for m in matches if 'adaptive/strategy.rs' not in m and '/tests/' not in m and not m.endswith('_test.rs')]
    return {'callsite_files': matches, 'traffic_callsite_files': traffic, 'status': 'live' if traffic else 'dead_registry_unreachable'}


def source_fallback(repo: Path):
    live=extract_live_profiles(repo)
    by_id={p['strategy_id']: p for p in live}
    probe=[]
    unresolved=0
    for sid in extract_probe_ids(repo):
        p=by_id.get(sid)
        if p:
            probe.append({'strategy_id':sid,'mapped_profile_name':p['name'],'status':'mapped'})
        else:
            probe.append({'strategy_id':sid,'mapped_profile_name':None,'status':'unresolved','unsupported_reasons':['unmapped_probe_strategy_id']})
            unresolved += 1
    dead=dead_registry_status(repo)
    dead_entries=[]
    if dead['status']=='dead_registry_unreachable':
        dead_entries.append({'name':'StrategyRegistry','status':'dead_registry_unreachable','unsupported_reasons':['no_runtime_callsite'],'callsite_files':dead['callsite_files']})
    return {'ok':True,'source':'source_fallback','live_profiles':live,'probe_numeric_ids':probe,'dead_registry_entries':dead_entries,'reconciliation':{'live_profiles_total':len(live),'probe_numeric_ids_total':len(probe),'numeric_ids_unresolved':unresolved,'dead_registry_entries_total':len(dead_entries),'failures':[]}}


def findings(inv):
    out=[]
    live=inv.get('live_profiles',[])
    names=[p.get('name') for p in live]
    dups=sorted({n for n in names if n and names.count(n)>1})
    if dups: out.append({'severity':'fail','message':f'duplicate live profile names: {dups}'})
    ids=[p.get('strategy_id') for p in live if p.get('strategy_id') is not None]
    dup_ids=sorted({i for i in ids if ids.count(i)>1})
    if dup_ids: out.append({'severity':'warn','message':f'duplicate live strategy ids: {dup_ids}'})
    unresolved=[x for x in inv.get('probe_numeric_ids',[]) if x.get('status')=='unresolved']
    if unresolved: out.append({'severity':'warn','message':f'{len(unresolved)} probe numeric ids do not map to live profiles: {[x.get("strategy_id") for x in unresolved]}'})
    dead=inv.get('dead_registry_entries',[])
    if dead: out.append({'severity':'info','message':f'{len(dead)} dead/unreachable registry spaces found'})
    return out


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--repo-root', default='..')
    ap.add_argument('--base-url', default='http://127.0.0.1:11337')
    ap.add_argument('--api-key', default='')
    ap.add_argument('--prefer-live', action='store_true')
    ap.add_argument('--out', default='strategy_inventory_reconcile.json')
    a=ap.parse_args()
    inv=None
    mode='source_fallback'
    if a.prefer_live:
        live=fetch(a.base_url,a.api_key)
        if live.get('ok'):
            inv=live; mode='live_api'
    if inv is None:
        inv=source_fallback(Path(a.repo_root))
    rep={'generated_at_utc':datetime.now(timezone.utc).isoformat(),'mode':mode,'inventory':inv,'findings':findings(inv)}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(rep,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps({'mode':mode,'live_profiles':len(inv.get('live_profiles',[])),'probe_ids':len(inv.get('probe_numeric_ids',[])),'findings':len(rep['findings'])},indent=2))
    return 1 if any(f['severity']=='fail' for f in rep['findings']) else 0
if __name__=='__main__': raise SystemExit(main())
