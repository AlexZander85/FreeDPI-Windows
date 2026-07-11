#!/usr/bin/env python3
import argparse, subprocess, json, time

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('command', choices=['run-one','run-all']); ap.add_argument('--strategy-id'); ap.add_argument('--api-base', default='http://127.0.0.1:11337')
    a=ap.parse_args()
    print(json.dumps({'status':'scaffold','command':a.command,'strategy_id':a.strategy_id,'note':'Use only for forced-combo smoke; not AutoTune validation.'},indent=2))
if __name__=='__main__': main()
