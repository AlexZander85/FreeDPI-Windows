#!/usr/bin/env python3
"""Observer-only flow telemetry checker.

Generates traffic with trafficgen_client.py, reads /qa/flow_telemetry before/after,
and verifies FreeDPI counters changed. It does not decide or tune strategies.
"""
from __future__ import annotations
import argparse, json, subprocess, sys, time, urllib.request, urllib.error
from pathlib import Path


def api_get(base, path, key=''):
    req=urllib.request.Request(base.rstrip()+path)
    if key: req.add_header('X-API-Key', key)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return {'ok':True,'body':json.loads(r.read() or b'{}')}
    except Exception as e:
        return {'ok':False,'error':repr(e)}

def total_counter(body):
    if not isinstance(body,dict): return 0
    agg=body.get('aggregate') or body.get('data',{}).get('aggregate') if isinstance(body.get('data'),dict) else body.get('aggregate')
    if not isinstance(agg,dict): return 0
    fields=['flows_observed','packets_received','packets_forwarded','packets_modified','packets_injected','packets_dropped','tls_outbound','dns_queries','quic_initial']
    return sum(int(agg.get(f) or 0) for f in fields)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--base',default='http://127.0.0.1:11337'); ap.add_argument('--api-key',default='')
    ap.add_argument('--scenario',choices=['http-get','tcp-connect','tls-handshake','dns-udp','udp-quic-like'],default='tcp-connect')
    ap.add_argument('--host',default='127.0.0.1'); ap.add_argument('--port',type=int,default=80)
    ap.add_argument('--url',default='http://127.0.0.1:8080/')
    ap.add_argument('--server-name',default='localhost'); ap.add_argument('--qname',default='example.com')
    ap.add_argument('--json-out',default='flow_telemetry_probe.json')
    a=ap.parse_args()
    before=api_get(a.base,'/qa/flow_telemetry',a.api_key)
    if not before.get('ok'):
        out={'status':'unsupported','reason':'qa_flow_telemetry_unreachable','before':before}
        Path(a.json_out).write_text(json.dumps(out,indent=2),encoding='utf-8'); print(json.dumps(out,indent=2)); return 2
    tg=Path(__file__).with_name('trafficgen_client.py')
    cmd=[sys.executable,str(tg),a.scenario]
    if a.scenario=='http-get': cmd+=['--url',a.url]
    elif a.scenario=='tcp-connect': cmd+=['--host',a.host,'--port',str(a.port)]
    elif a.scenario=='tls-handshake': cmd+=['--host',a.host,'--port',str(a.port),'--server-name',a.server_name]
    elif a.scenario=='dns-udp': cmd+=['--server',a.host,'--port',str(a.port),'--qname',a.qname]
    elif a.scenario=='udp-quic-like': cmd+=['--host',a.host,'--port',str(a.port)]
    traffic=subprocess.run(cmd,text=True,capture_output=True,timeout=30)
    time.sleep(0.5)
    after=api_get(a.base,'/qa/flow_telemetry',a.api_key)
    b=total_counter(before.get('body')); c=total_counter(after.get('body')) if after.get('ok') else b
    
    # Check recent flows for causal verification
    recent_ok = False
    if after.get('ok') and isinstance(after['body'], dict):
        recent_flows = after['body'].get('recent_flows', [])
        expected_proto = 'tcp' if a.scenario in ['tcp-connect', 'http-get', 'tls-handshake'] else 'udp'
        for flow in recent_flows:
            if isinstance(flow, dict):
                if flow.get('protocol') == expected_proto and flow.get('observed_by_windivert') is True:
                    recent_ok = True
                    break

    # Pass only if counters grew and a matching recent flow was recorded in the ring buffer
    status='pass' if (c>b and recent_ok) else 'fail'
    out={'status':status,'before_score':b,'after_score':c,'recent_flow_matched':recent_ok,'traffic_returncode':traffic.returncode,'traffic_stdout':traffic.stdout[-4000:],'traffic_stderr':traffic.stderr[-4000:],'before':before,'after':after}
    Path(a.json_out).write_text(json.dumps(out,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps({'status':status,'before_score':b,'after_score':c,'recent_flow_matched':recent_ok},indent=2))
    return 0 if status=='pass' else 1
if __name__=='__main__': raise SystemExit(main())
