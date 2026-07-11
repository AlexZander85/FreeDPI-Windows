#!/usr/bin/env python3
import argparse,subprocess,json

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--log', default='Application'); ap.add_argument('--count', type=int, default=100)
    a=ap.parse_args(); cmd=['wevtutil','qe',a.log,'/f:Text',f'/c:{a.count}']
    p=subprocess.run(cmd,text=True,capture_output=True)
    print(json.dumps({'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr},indent=2))
if __name__=='__main__': main()
