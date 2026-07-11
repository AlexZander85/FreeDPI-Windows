#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,urllib.request,urllib.error
from typing import Any

class RestClient:
    def __init__(self, base: str='http://127.0.0.1:11337', api_key: str=''):
        self.base=base.rstrip('/'); self.api_key=api_key
    def request(self, method: str, path: str, data: Any=None, timeout: int=10) -> dict[str, Any]:
        body=None if data is None else json.dumps(data).encode('utf-8')
        req=urllib.request.Request(self.base+path, data=body, method=method.upper())
        req.add_header('Content-Type','application/json')
        if self.api_key: req.add_header('X-API-Key', self.api_key)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw=r.read() or b'{}'
                return {'ok':True,'status':r.status,'data':json.loads(raw)}
        except Exception as e:
            return {'ok':False,'error':repr(e)}
    def get(self,path): return self.request('GET', path)
    def post(self,path,data=None): return self.request('POST', path, data or {})

def request(base, method, path, api_key='', data=None):
    return RestClient(base, api_key).request(method, path, data)

def envelope_data(response: dict[str, Any]) -> Any:
    if not response.get('ok'): return None
    body=response.get('data')
    if isinstance(body, dict) and {'ok','data','error'}.issubset(body.keys()):
        return body.get('data')
    return body

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('method'); ap.add_argument('path'); ap.add_argument('--base', default='http://127.0.0.1:11337'); ap.add_argument('--api-key', default=''); ap.add_argument('--json', default=None)
    a=ap.parse_args(); data=json.loads(a.json) if a.json else None
    print(json.dumps(request(a.base,a.method.upper(),a.path,a.api_key,data),indent=2,ensure_ascii=False))
if __name__=='__main__': main()
