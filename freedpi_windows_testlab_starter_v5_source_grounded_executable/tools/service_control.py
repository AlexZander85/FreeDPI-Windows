#!/usr/bin/env python3
import argparse,subprocess,json

def run(cmd):
    p=subprocess.run(cmd,text=True,capture_output=True)
    return {'cmd':cmd,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('action', choices=['query','start','stop','restart','delete']); ap.add_argument('--name', default='FreeDPI')
    a=ap.parse_args()
    if a.action=='restart': cmds=[['sc.exe','stop',a.name],['sc.exe','start',a.name]]
    elif a.action=='delete': cmds=[['sc.exe','delete',a.name]]
    else: cmds=[['sc.exe',a.action,a.name]]
    print(json.dumps([run(c) for c in cmds],indent=2))
if __name__=='__main__': main()
