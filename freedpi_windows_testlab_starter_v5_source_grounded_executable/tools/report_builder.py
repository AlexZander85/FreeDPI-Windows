#!/usr/bin/env python3
import argparse,json
from pathlib import Path

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--results-dir', required=True)
    a=ap.parse_args(); d=Path(a.results_dir); rows=[]
    p=d/'results.jsonl'
    if p.exists(): rows=[json.loads(x) for x in p.read_text(encoding='utf-8').splitlines() if x.strip()]
    report={'total_events':len(rows),'events':rows}
    (d/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    (d/'report.md').write_text('# Testlab Report\n\nTotal events: '+str(len(rows))+'\n',encoding='utf-8')
if __name__=='__main__': main()
