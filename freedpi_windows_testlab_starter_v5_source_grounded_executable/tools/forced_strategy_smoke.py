#!/usr/bin/env python3
"""Forced strategy smoke runner.

Allowed only for smoke/deep strategy verification. Must never be used by AutoTune causal tests.
It uses production `/api/v1/strategies/tune` when available and verifies runtime snapshot/telemetry if QA hooks exist.
"""
from __future__ import annotations
import argparse, json, subprocess, sys, urllib.request, urllib.error, time
from pathlib import Path


def call(base, method, path, key='', data=None):
    body=None if data is None else json.dumps(data).encode()
    req=urllib.request.Request(base.rstrip()+path, data=body, method=method)
    req.add_header('Content-Type','application/json')
    if key: req.add_header('X-API-Key',key)
    try:
        with urllib.request.urlopen(req,timeout=8) as r:
            return {'ok':True,'status':r.status,'body':json.loads(r.read() or b'{}')}
    except Exception as e:
        return {'ok':False,'error':repr(e)}


def inventory(base,key,repo,outdir):
    script=Path(__file__).with_name('strategy_inventory_reconcile.py')
    out=outdir/'inventory.json'
    p=subprocess.run([sys.executable,str(script),'--prefer-live','--base-url',base,'--api-key',key,'--repo-root',repo,'--out',str(out)],text=True,capture_output=True)
    return json.loads(out.read_text(encoding='utf-8'))['inventory']


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--base',default='http://127.0.0.1:11337'); ap.add_argument('--api-key',default=''); ap.add_argument('--repo-root',default='..'); ap.add_argument('--out-dir',default='forced_strategy_smoke'); ap.add_argument('--limit',type=int,default=0)
    a=ap.parse_args(); outdir=Path(a.out_dir); outdir.mkdir(parents=True,exist_ok=True)
    inv=inventory(a.base,a.api_key,a.repo_root,outdir)
    rows=[]
    profiles=[p for p in inv.get('live_profiles',[]) if p.get('strategy_id') is not None]
    if a.limit: profiles=profiles[:a.limit]
    for p in profiles:
        sid=p['strategy_id']; name=p.get('name')
        tune=call(a.base,'POST','/api/v1/strategies/tune',a.api_key,{'strategy_id':sid,'params':{},'persist':False})
        if not tune.get('ok'):
            rows.append({'strategy_id':sid,'name':name,'status':'unsupported','unsupported_reasons':['production_tune_endpoint_unreachable'],'details':tune}); continue
        snap=call(a.base,'GET','/qa/runtime_strategy_snapshot',a.api_key)
        telemetry_before=call(a.base,'GET','/qa/flow_telemetry',a.api_key)
        tg=Path(__file__).with_name('trafficgen_client.py')
        traffic=subprocess.run([sys.executable,str(tg),'tcp-connect','--host','127.0.0.1','--port','80'],text=True,capture_output=True,timeout=15)
        time.sleep(0.2)
        telemetry_after=call(a.base,'GET','/qa/flow_telemetry',a.api_key)
        if not snap.get('ok'):
            status='unsupported'; reasons=['runtime_snapshot_missing']
        elif not telemetry_after.get('ok'):
            status='unsupported'; reasons=['flow_telemetry_missing']
        else:
            forced = snap.get('body', {}).get('forced', {})
            if forced.get('strategy_id') != sid:
                status='fail'
                reasons=['forced_strategy_id_mismatch']
            else:
                status='pass'
                reasons=[]
        rows.append({'strategy_id':sid,'name':name,'status':status,'unsupported_reasons':reasons,'tune':tune,'snapshot':snap,'traffic_rc':traffic.returncode,'telemetry_before':telemetry_before,'telemetry_after':telemetry_after})
    report={'total':len(rows),'pass':sum(1 for r in rows if r['status']=='pass'),'unsupported':sum(1 for r in rows if r['status']=='unsupported'),'rows':rows}
    (outdir/'forced_strategy_smoke.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('total','pass','unsupported')},indent=2))
    return 0 if report['pass'] else 2
if __name__=='__main__': raise SystemExit(main())
