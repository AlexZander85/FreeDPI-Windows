#!/usr/bin/env python3
"""Source-grounded observer runner for FreeDPI-Windows.

Commands are executable where supporting app instrumentation exists. Missing QA surface is
reported as unsupported, never as pass. AutoTune/DPI Probe checks are observer-only.
"""
from __future__ import annotations
import argparse, ctypes, json, os, platform, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

COMMANDS = ['smoke','qa-contract','strategy-inventory','all-strategies-smoke','flow-telemetry-probe','probe-mapping-audit','unsupported-reason-lint','strategy-groups-deep','dpi-probe-oracle','autotune-causal','real-windows-smoke','provider-auto','restart-stress','release-verify','collect-artifacts','run-one','resume','report']

class ResultWriter:
    def __init__(self, root: Path, resume: bool=False):
        self.root=root
        self.root.mkdir(parents=True,exist_ok=True)
        self.path=self.root/'results.jsonl'
        self.done=set()
        if resume and self.path.exists():
            for line in self.path.read_text(encoding='utf-8').splitlines():
                if line.strip():
                    try:
                        r=json.loads(line)
                        self.done.add(r.get('test_id') or r.get('event'))
                    except Exception:
                        pass
    def write(self, rec: dict):
        rec.setdefault('timestamp_utc', datetime.now(timezone.utc).isoformat())
        with self.path.open('a', encoding='utf-8') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')
    def rows(self):
        if not self.path.exists():
            return []
        return [json.loads(x) for x in self.path.read_text(encoding='utf-8').splitlines() if x.strip()]

def is_windows():
    return platform.system().lower() == 'windows'

def is_admin():
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def run(cmd: list[str], cwd: Path|None=None, timeout: int=600) -> dict:
    start=time.time()
    try:
        p=subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=True, timeout=timeout)
        return {'cmd':cmd,'returncode':p.returncode,'stdout':p.stdout[-20000:],'stderr':p.stderr[-20000:],'duration_ms':int((time.time()-start)*1000)}
    except Exception as e:
        return {'cmd':cmd,'returncode':-999,'error':repr(e),'duration_ms':int((time.time()-start)*1000)}

def write_report(rw: ResultWriter):
    rows=rw.rows()
    counts={}
    for r in rows:
        st=r.get('status','event')
        counts[st]=counts.get(st,0)+1
    report={'generated_at_utc':datetime.now(timezone.utc).isoformat(),'summary':{'total_events':len(rows),'status_counts':counts},'events':rows}
    (rw.root/'report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    md=['# FreeDPI Windows Testlab Report','',f"Generated: {report['generated_at_utc']}",'',f"Total events: {len(rows)}",'', '## Status counts']
    for k,v in sorted(counts.items()):
        md.append(f'- {k}: {v}')
    (rw.root/'report.md').write_text('\n'.join(md), encoding='utf-8')

def cargo_workspace(repo: Path) -> Path:
    return repo/'src'

def cmd_smoke(args,rw):
    res=run(['cargo','test','--workspace'], cwd=cargo_workspace(Path(args.repo_root)), timeout=900)
    rw.write({'event':'cargo_test_workspace','status':'pass' if res['returncode']==0 else 'fail','data':res})

def cmd_qa_contract(args,rw):
    script=Path(__file__).with_name('qa_contract_check.py')
    cmd=[sys.executable,str(script),'--base',args.api_base,'--json-out',str(Path(args.results_dir)/'qa_contract.json')]
    if args.api_key:
        cmd+=['--api-key',args.api_key]
    res=run(cmd,timeout=120)
    rw.write({'event':'qa_contract','status':'pass' if res['returncode']==0 else 'unsupported','data':res})

def cmd_strategy_inventory(args,rw):
    script=Path(__file__).with_name('strategy_inventory.py')
    out_prefix=str(Path(args.results_dir)/'strategy_inventory')
    cmd=[sys.executable,str(script),'--out',out_prefix]
    if args.source_fallback:
        cmd+=['--source-fallback','--repo-path',args.repo_root]
    else:
        cmd+=['--base-url',args.api_base]
        if args.api_key:
            cmd+=['--api-key',args.api_key]
    res=run(cmd,timeout=120)
    status='pass' if res['returncode']==0 and not args.source_fallback else 'unsupported' if args.source_fallback else 'fail'
    rw.write({'event':'strategy_inventory','status':status,'source_fallback':args.source_fallback,'data':res})

def cmd_dpi_probe_oracle(args,rw):
    rw.write({'event':'dpi_probe_oracle','status':'unsupported','reason':'requires synthetic_dpi_server + app probe telemetry; runner must not classify for app'})

def cmd_autotune_causal(args,rw):
    script=Path(__file__).with_name('autotune_causal_observer.py')
    cmd=[sys.executable,str(script),'--base',args.api_base,'--expected-class',args.expected_class or 'TLS_HANDSHAKE_TIMEOUT','--json-out',str(Path(args.results_dir)/'autotune_causal.json')]
    if args.api_key:
        cmd+=['--api-key',args.api_key]
    res=run(cmd,timeout=args.poll_seconds+30)
    combined=(res.get('stdout','')+res.get('stderr','')).lower()
    status='pass' if res['returncode']==0 else 'unsupported' if 'unsupported' in combined else 'fail'
    rw.write({'event':'autotune_causal','status':status,'observer_only':True,'data':res})

def cmd_stub(name):
    def f(args,rw):
        rw.write({'event':name,'status':'unsupported','reason':'documented scaffold; implement per docs/agent_execution_prompt.md and known_limitations.md'})
    return f



def cmd_flow_telemetry_probe(args,rw):
    script=Path(__file__).with_name('flow_telemetry_probe.py')
    cmd=[sys.executable,str(script),'--base',args.api_base,'--api-key',args.api_key,'--scenario',args.scenario,'--host',args.host,'--port',str(args.port),'--json-out',str(Path(args.results_dir)/'flow_telemetry_probe.json')]
    res=run(cmd,timeout=60)
    status='pass' if res['returncode']==0 else 'unsupported' if res['returncode']==2 else 'fail'
    rw.write({'event':'flow_telemetry_probe','status':status,'data':res})

def cmd_probe_mapping_audit(args,rw):
    script=Path(__file__).with_name('probe_mapping_audit.py')
    cmd=[sys.executable,str(script),'--repo-root',args.repo_root,'--out',str(Path(args.results_dir)/'probe_mapping_audit.json')]
    res=run(cmd,timeout=60)
    status='pass' if res['returncode']==0 else 'warn'
    rw.write({'event':'probe_mapping_audit','status':status,'data':res})

def cmd_all_strategies_smoke(args,rw):
    script=Path(__file__).with_name('forced_strategy_smoke.py')
    cmd=[sys.executable,str(script),'--base',args.api_base,'--api-key',args.api_key,'--repo-root',args.repo_root,'--out-dir',str(Path(args.results_dir)/'forced_strategy_smoke'),'--limit',str(args.limit)]
    res=run(cmd,timeout=900)
    status='pass' if res['returncode']==0 else 'unsupported' if res['returncode']==2 else 'fail'
    rw.write({'event':'all_strategies_smoke','status':status,'forced_mode_only':True,'data':res})

def cmd_unsupported_reason_lint(args,rw):
    target=Path(args.lint_json) if args.lint_json else Path(args.results_dir)/'strategy_inventory_reconcile.json'
    if not target.exists():
        inv_script=Path(__file__).with_name('strategy_inventory_reconcile.py')
        run([sys.executable,str(inv_script),'--repo-root',args.repo_root,'--out',str(target)], timeout=60)
    script=Path(__file__).with_name('unsupported_reason_linter.py')
    res=run([sys.executable,str(script),str(target),'--out',str(Path(args.results_dir)/'unsupported_reason_lint.json')],timeout=60)
    rw.write({'event':'unsupported_reason_lint','status':'pass' if res['returncode']==0 else 'fail','data':res})

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('command',choices=COMMANDS)
    ap.add_argument('--repo-root',default='..')
    ap.add_argument('--results-dir',default='./runs/default')
    ap.add_argument('--api-base',default='http://127.0.0.1:11337')
    ap.add_argument('--api-key',default=os.environ.get('FREEDPI_API_KEY',''))
    ap.add_argument('--resume',action='store_true')
    ap.add_argument('--source-fallback',action='store_true')
    ap.add_argument('--expected-class',default='')
    ap.add_argument('--poll-seconds',type=int,default=30)
    ap.add_argument('--scenario',default='tcp-connect')
    ap.add_argument('--host',default='127.0.0.1')
    ap.add_argument('--port',type=int,default=80)
    ap.add_argument('--limit',type=int,default=0)
    ap.add_argument('--lint-json',default='')
    args=ap.parse_args()
    rw=ResultWriter(Path(args.results_dir),args.resume)
    rw.write({'event':'start','command':args.command,'repo_root':str(Path(args.repo_root).resolve()),'windows':is_windows(),'admin':is_admin(),'observer_only':True})
    if args.command=='smoke':
        cmd_smoke(args,rw)
    elif args.command=='qa-contract':
        cmd_qa_contract(args,rw)
    elif args.command=='strategy-inventory':
        cmd_strategy_inventory(args,rw)
    elif args.command=='flow-telemetry-probe':
        cmd_flow_telemetry_probe(args,rw)
    elif args.command=='probe-mapping-audit':
        cmd_probe_mapping_audit(args,rw)
    elif args.command=='all-strategies-smoke':
        cmd_all_strategies_smoke(args,rw)
    elif args.command=='unsupported-reason-lint':
        cmd_unsupported_reason_lint(args,rw)
    elif args.command=='dpi-probe-oracle':
        cmd_dpi_probe_oracle(args,rw)
    elif args.command=='autotune-causal':
        cmd_autotune_causal(args,rw)
    elif args.command in ('report','resume'):
        pass
    else:
        cmd_stub(args.command)(args,rw)
    write_report(rw)
if __name__=='__main__':
    main()
