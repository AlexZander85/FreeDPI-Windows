#!/usr/bin/env python3
"""Check minimal QA observer API contract.

Accepts current repo flat JSON convention. Does not require the older envelope shape.
"""
from __future__ import annotations
import argparse, json, urllib.request, urllib.error
from pathlib import Path
from typing import Any

REQUIRED_GET=['/qa/capabilities','/qa/health','/qa/strategy_inventory','/qa/runtime_strategy_snapshot','/qa/flow_telemetry','/qa/autotune_state','/qa/autotune_decision_log','/qa/windivert_stats','/qa/driver_service_stats']
REQUIRED_POST=['/qa/reset_state','/qa/reset_telemetry','/qa/export_test_report']
FORBIDDEN=['/qa/force_strategy','/qa/start','/qa/stop','/qa/restart','/qa/service_state']

def call(base, method, path, data=None, api_key=''):
    body=None if data is None else json.dumps(data).encode()
    req=urllib.request.Request(base.rstrip()+path, data=body, method=method)
    req.add_header('Content-Type','application/json')
    if api_key: req.add_header('X-API-Key',api_key)
    try:
        with urllib.request.urlopen(req,timeout=5) as r:
            raw=r.read() or b'{}'
            return {'reachable':True,'status':r.status,'body':json.loads(raw)}
    except urllib.error.HTTPError as e:
        return {'reachable':False,'status':e.code,'error':str(e)}
    except Exception as e:
        return {'reachable':False,'error':repr(e)}

def check_response(path: str, res: dict[str, Any], supported_map: dict[str, bool]) -> bool:
    if not res.get('reachable'): return False
    b=res.get('body')
    if not isinstance(b,dict): return False
    cap_name=path.replace('/qa/','')
    if cap_name in supported_map and not supported_map[cap_name]:
        return b.get('ok') is False and b.get('unsupported') is True
    return b.get('ok') is True

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--base',default='http://127.0.0.1:11337'); ap.add_argument('--api-key',default=''); ap.add_argument('--json-out',default='qa_contract.json')
    a=ap.parse_args(); rows=[]
    
    # 1. Fetch capabilities first
    cap_res=call(a.base,'GET','/qa/capabilities',api_key=a.api_key)
    supported_map={}
    if cap_res.get('reachable') and isinstance(cap_res.get('body'), dict):
        caps=cap_res['body'].get('capabilities', [])
        for cap in caps:
            if isinstance(cap, dict) and 'name' in cap and 'supported' in cap:
                supported_map[cap['name']]=cap['supported']

    for p in REQUIRED_GET:
        r=call(a.base,'GET',p,api_key=a.api_key)
        rows.append({'method':'GET','path':p,'required':True,'flat_ok':check_response(p,r,supported_map),'result':r})
    for p in REQUIRED_POST:
        r=call(a.base,'POST',p,{},api_key=a.api_key)
        rows.append({'method':'POST','path':p,'required':True,'flat_ok':check_response(p,r,supported_map),'result':r})
        
    forbidden=[]
    for p in FORBIDDEN:
        for m in ('GET','POST'):
            r=call(a.base,m,p,{},api_key=a.api_key)
            if r.get('reachable'): forbidden.append({'method':m,'path':p,'result':r})
            
    summary={'required_total':len(rows),'required_flat_ok':sum(1 for r in rows if r['flat_ok']),'forbidden_reachable':len(forbidden)}
    out={'ok':summary['required_total']==summary['required_flat_ok'] and not forbidden,'summary':summary,'endpoints':rows,'forbidden':forbidden}
    Path(a.json_out).write_text(json.dumps(out,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps(summary,indent=2))
    return 0 if out['ok'] else 2
if __name__=='__main__': raise SystemExit(main())
