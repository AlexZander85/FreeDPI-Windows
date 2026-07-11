#!/usr/bin/env python3
import argparse,re,hashlib,json,secrets
from pathlib import Path
IP_RE=re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_RE=re.compile(r'\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
TOKEN_RE=re.compile(r'(?i)(api[_-]?key|authorization|cookie|token)[:=][^\s,;]+')
def h(s,salt): return hashlib.sha256((salt+s).encode()).hexdigest()[:16]
def redact_text(t,salt):
    t=TOKEN_RE.sub(lambda m:m.group(1)+'=<redacted>',t)
    t=IP_RE.sub(lambda m:'ip#'+h(m.group(0),salt),t)
    t=DOMAIN_RE.sub(lambda m:'domain#'+h(m.group(0),salt),t)
    return t
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('input'); ap.add_argument('--out', required=True); ap.add_argument('--salt', default=None)
    a=ap.parse_args(); salt=a.salt or secrets.token_hex(16)
    p=Path(a.input); data=p.read_text(encoding='utf-8',errors='replace')
    Path(a.out).write_text(redact_text(data,salt),encoding='utf-8')
    Path(str(a.out)+'.manifest.json').write_text(json.dumps({'salt_hash':hashlib.sha256(salt.encode()).hexdigest(),'rules':['ip','domain','token_cookie_auth']},indent=2),encoding='utf-8')
if __name__=='__main__': main()
