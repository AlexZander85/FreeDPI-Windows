#!/usr/bin/env python3
import argparse, subprocess, json, pathlib

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('action', choices=['start','stop']); ap.add_argument('--out-dir', default='./runs/trace'); ap.add_argument('--allow-raw-capture', action='store_true')
    a=ap.parse_args(); pathlib.Path(a.out_dir).mkdir(parents=True, exist_ok=True)
    if not a.allow_raw_capture:
        print(json.dumps({'ok':False,'reason':'raw_capture_requires_allow_raw_capture'})); return
    cmd=['netsh','trace','start','capture=yes','report=no',f'tracefile={a.out_dir}\\freedpi_trace.etl'] if a.action=='start' else ['netsh','trace','stop']
    p=subprocess.run(cmd,text=True,capture_output=True)
    print(json.dumps({'cmd':cmd,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr},indent=2))
if __name__=='__main__': main()
