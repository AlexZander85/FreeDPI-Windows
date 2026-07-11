#!/usr/bin/env python3
"""Observer-only AutoTune causal verifier.
It never calls /qa/force_strategy. It fails if decision logs show external intervention.
"""
from __future__ import annotations
import argparse, json, time, urllib.request
from typing import Any

FORBIDDEN_ENDPOINTS = {'/qa/force_strategy'}

class Rest:
    def __init__(self, base: str, api_key: str=''):
        self.base=base.rstrip('/'); self.api_key=api_key; self.calls=[]
    def request(self, method: str, path: str, body: Any=None):
        if path in FORBIDDEN_ENDPOINTS:
            raise RuntimeError('external_strategy_intervention: attempted '+path)
        self.calls.append({'method':method,'path':path})
        data=None if body is None else json.dumps(body).encode('utf-8')
        req=urllib.request.Request(self.base+path, data=data, method=method)
        req.add_header('Content-Type','application/json')
        if self.api_key: req.add_header('X-API-Key', self.api_key)
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read() or b'{}')
    def get(self,path): return self.request('GET',path)
    def post(self,path,body=None): return self.request('POST',path,body or {})


def data(env: dict[str, Any]) -> Any:
    return env.get('data') if isinstance(env, dict) else None


def fail(reason: str, **extra):
    return {'status':'fail','reason':reason,**extra}

def unsupported(reason: str, **extra):
    return {'status':'unsupported','reason':reason,**extra}


def verify_chain(events: list[dict[str, Any]], snapshot: dict[str, Any], flow: dict[str, Any], expected_class: str) -> dict[str, Any]:
    if any(e.get('external_intervention') or e.get('selected_by') == 'runner' or e.get('source') == 'forced_test' for e in events):
        return fail('external_strategy_intervention', events=events)
    phases={e.get('phase') for e in events}
    if not ({'detect','probe'} & phases): return fail('missing_detect_or_probe_event', phases=list(phases))
    if 'candidate' not in phases: return fail('missing_candidate_event', phases=list(phases))
    if not ({'canary','promote','rollback','cooldown'} & phases): return fail('missing_rollout_event', phases=list(phases))
    if expected_class and not any(e.get('block_class') == expected_class for e in events):
        return fail('missing_expected_block_class', expected=expected_class)
    if not snapshot or snapshot.get('selected_by') not in ('app','app_autotune',None):
        return fail('runtime_snapshot_not_app_selected', snapshot=snapshot)
    if not flow or (flow.get('observed_flows',0) == 0 and flow.get('processed_flows',0) == 0):
        return fail('missing_flow_telemetry', flow=flow)
    return {'status':'pass','phases':sorted(str(p) for p in phases),'events':len(events)}


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--base', default='http://127.0.0.1:11337')
    ap.add_argument('--api-key', default='')
    ap.add_argument('--expected-class', required=True)
    ap.add_argument('--target-url', default='http://127.0.0.1:18080/')
    ap.add_argument('--poll-seconds', type=int, default=30)
    ap.add_argument('--json-out', default='')
    a=ap.parse_args()
    rest=Rest(a.base,a.api_key)
    try:
        rest.post('/qa/reset_state')
        rest.post('/qa/reset_telemetry')
        rest.post('/qa/start_auto')
    except Exception as e:
        result=unsupported('qa_api_unavailable_or_incomplete', error=repr(e))
        print(json.dumps(result,indent=2)); return 2
    deadline=time.time()+a.poll_seconds
    last_events=[]; snapshot={}; flow={}
    while time.time() < deadline:
        try:
            last_events = data(rest.get('/qa/autotune_decision_log')) or []
            snapshot = data(rest.get('/qa/runtime_strategy_snapshot')) or {}
            flow = data(rest.get('/qa/flow_telemetry')) or {}
            result=verify_chain(last_events, snapshot, flow, a.expected_class)
            if result['status']=='pass': break
        except Exception as e:
            result=unsupported('qa_read_endpoint_failed', error=repr(e)); break
        time.sleep(1)
    else:
        result=fail('causal_chain_timeout', last_events=last_events, snapshot=snapshot, flow=flow)
    result['runner_calls']=rest.calls
    if any(c['path']=='/qa/force_strategy' for c in rest.calls):
        result=fail('external_strategy_intervention', runner_calls=rest.calls)
    if a.json_out:
        open(a.json_out,'w',encoding='utf-8').write(json.dumps(result,indent=2,ensure_ascii=False))
    print(json.dumps(result,indent=2,ensure_ascii=False))
    return 0 if result['status']=='pass' else 2

if __name__ == '__main__':
    raise SystemExit(main())
