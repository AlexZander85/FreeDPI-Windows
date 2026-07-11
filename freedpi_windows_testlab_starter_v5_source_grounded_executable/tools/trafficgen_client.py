#!/usr/bin/env python3
"""trafficgen_client.py — deterministic layered traffic generator for FreeDPI-Windows testlab.

This tool is intentionally NOT a strategy selector. It generates traffic and writes
machine-readable observations. FreeDPI's own telemetry/decision log must prove whether
the flow was intercepted, classified and handled.

Scenarios:
  http-get       Plain HTTP GET using stdlib urllib
  tcp-connect    TCP connect + optional payload
  tls-handshake  TLS client handshake using stdlib ssl
  dns-udp        Minimal UDP DNS A query
  udp-quic-like  UDP datagram shaped like a QUIC v1 Initial enough for capture/filter smoke
  batch          Execute a JSON/YAML-ish matrix file with scenario objects

Outputs a JSON document to stdout and optionally --json-out.
"""
from __future__ import annotations
import argparse, json, socket, ssl, sys, time, urllib.request, urllib.error
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

try:
    import yaml  # optional; runner works without it for JSON matrices
except Exception:
    yaml = None

@dataclass
class Observation:
    scenario: str
    ok: bool
    target: str
    elapsed_ms: int
    status: int | None = None
    bytes_read: int = 0
    error: str | None = None
    extra: dict[str, Any] | None = None


def now_ms() -> float:
    return time.time() * 1000.0


def http_get(url: str, timeout: float, headers: dict[str,str] | None=None) -> Observation:
    t = now_ms()
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(4096)
            return Observation('http-get', True, url, int(now_ms()-t), getattr(r,'status',None), len(body), extra={'headers': dict(r.headers)})
    except Exception as e:
        return Observation('http-get', False, url, int(now_ms()-t), error=repr(e))


def tcp_connect(host: str, port: int, timeout: float, payload: bytes=b'', read: bool=True) -> Observation:
    target=f'{host}:{port}'
    t=now_ms()
    s=None
    try:
        s=socket.create_connection((host,port), timeout=timeout)
        s.settimeout(timeout)
        if payload:
            s.sendall(payload)
        data=b''
        if read:
            try: data=s.recv(4096)
            except socket.timeout: pass
        return Observation('tcp-connect', True, target, int(now_ms()-t), bytes_read=len(data), extra={'sent_bytes': len(payload)})
    except Exception as e:
        return Observation('tcp-connect', False, target, int(now_ms()-t), error=repr(e), extra={'sent_bytes': len(payload)})
    finally:
        if s:
            try: s.close()
            except OSError: pass


def tls_handshake(host: str, port: int, server_name: str, timeout: float, alpn: list[str] | None=None, insecure: bool=True) -> Observation:
    target=f'{host}:{port}/{server_name}'
    t=now_ms()
    raw=None
    try:
        raw=socket.create_connection((host,port), timeout=timeout)
        ctx=ssl.create_default_context()
        if insecure:
            ctx.check_hostname=False
            ctx.verify_mode=ssl.CERT_NONE
        if alpn:
            ctx.set_alpn_protocols(alpn)
        with ctx.wrap_socket(raw, server_hostname=server_name) as ss:
            selected = ss.selected_alpn_protocol()
            cipher = ss.cipher()
            return Observation('tls-handshake', True, target, int(now_ms()-t), extra={'alpn': selected, 'cipher': cipher})
    except Exception as e:
        return Observation('tls-handshake', False, target, int(now_ms()-t), error=repr(e))
    finally:
        try:
            if raw: raw.close()
        except OSError:
            pass


def encode_dns_name(name: str) -> bytes:
    parts=name.strip('.').split('.')
    out=b''
    for p in parts:
        b=p.encode('idna')
        if len(b)>63: raise ValueError('DNS label too long')
        out += bytes([len(b)]) + b
    return out + b'\x00'


def dns_udp(server: str, port: int, qname: str, timeout: float, qtype: int=1) -> Observation:
    target=f'{server}:{port}/{qname}'
    t=now_ms()
    txid=0x4242
    query = txid.to_bytes(2,'big') + b'\x01\x00' + b'\x00\x01\x00\x00\x00\x00\x00\x00' + encode_dns_name(qname) + qtype.to_bytes(2,'big') + b'\x00\x01'
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query,(server,port))
        data,addr=s.recvfrom(4096)
        rcode=data[3] & 0x0f if len(data)>=4 else None
        return Observation('dns-udp', True, target, int(now_ms()-t), bytes_read=len(data), extra={'rcode': rcode, 'from': f'{addr[0]}:{addr[1]}'})
    except Exception as e:
        return Observation('dns-udp', False, target, int(now_ms()-t), error=repr(e))
    finally:
        s.close()


def quic_like_initial_payload(dcid: bytes=b'freedpi1', scid: bytes=b'client01') -> bytes:
    # QUIC long header, fixed bit set, Initial type (0x00), version 1.
    # This is not a cryptographically valid QUIC Initial. It is a capture/filter smoke datagram only.
    first = 0xC0
    version = (1).to_bytes(4,'big')
    payload = bytes([first]) + version + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    payload += b'\x00'  # token length varint 0
    payload += b'\x40\x10'  # length-ish varint placeholder
    payload += b'\x00\x00\x00\x01'  # packet number placeholder
    if len(payload) < 1200:
        payload += b'\x00' * (1200-len(payload))
    return payload


def udp_quic_like(host: str, port: int, timeout: float, count: int=1) -> Observation:
    target=f'{host}:{port}'
    t=now_ms()
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    payload=quic_like_initial_payload()
    sent=0
    got=0
    try:
        for _ in range(count):
            sent += s.sendto(payload,(host,port))
        try:
            while True:
                data,addr=s.recvfrom(4096)
                got += len(data)
                break
        except socket.timeout:
            pass
        return Observation('udp-quic-like', True, target, int(now_ms()-t), bytes_read=got, extra={'datagrams': count, 'sent_bytes': sent, 'note': 'not cryptographically valid; capture/filter smoke only'})
    except Exception as e:
        return Observation('udp-quic-like', False, target, int(now_ms()-t), error=repr(e))
    finally:
        s.close()


def run_scenario(obj: dict[str,Any], default_timeout: float) -> Observation:
    typ=obj.get('type') or obj.get('scenario')
    timeout=float(obj.get('timeout', default_timeout))
    if typ=='http-get':
        return http_get(obj['url'], timeout, obj.get('headers'))
    if typ=='tcp-connect':
        payload=(obj.get('payload') or '').encode('utf-8')
        return tcp_connect(obj.get('host','127.0.0.1'), int(obj.get('port',80)), timeout, payload, bool(obj.get('read',True)))
    if typ=='tls-handshake':
        return tls_handshake(obj.get('host','127.0.0.1'), int(obj.get('port',443)), obj.get('server_name') or obj.get('host','localhost'), timeout, obj.get('alpn'), bool(obj.get('insecure',True)))
    if typ=='dns-udp':
        return dns_udp(obj.get('server','127.0.0.1'), int(obj.get('port',53)), obj.get('qname','example.com'), timeout, int(obj.get('qtype',1)))
    if typ=='udp-quic-like':
        return udp_quic_like(obj.get('host','127.0.0.1'), int(obj.get('port',443)), timeout, int(obj.get('count',1)))
    raise SystemExit(f'unsupported scenario type: {typ!r}')


def load_matrix(path: Path) -> list[dict[str,Any]]:
    text=path.read_text(encoding='utf-8')
    if path.suffix.lower() in ('.yaml','.yml') and yaml:
        data=yaml.safe_load(text)
    else:
        data=json.loads(text)
    if isinstance(data, dict):
        return data.get('scenarios') or data.get('tests') or []
    if isinstance(data, list):
        return data
    raise SystemExit('matrix must be a list or object with scenarios/tests')


def main():
    ap=argparse.ArgumentParser()
    sub=ap.add_subparsers(dest='cmd', required=True)
    def common(p):
        p.add_argument('--timeout',type=float,default=5)
        p.add_argument('--json-out',type=Path)
    p=sub.add_parser('http-get'); common(p); p.add_argument('--url',required=True); p.add_argument('--count',type=int,default=1)
    p=sub.add_parser('tcp-connect'); common(p); p.add_argument('--host',default='127.0.0.1'); p.add_argument('--port',type=int,required=True); p.add_argument('--payload',default=''); p.add_argument('--no-read',action='store_true')
    p=sub.add_parser('tls-handshake'); common(p); p.add_argument('--host',default='127.0.0.1'); p.add_argument('--port',type=int,default=443); p.add_argument('--server-name',default='localhost'); p.add_argument('--alpn',action='append')
    p=sub.add_parser('dns-udp'); common(p); p.add_argument('--server',default='127.0.0.1'); p.add_argument('--port',type=int,default=53); p.add_argument('--qname',default='example.com'); p.add_argument('--qtype',type=int,default=1)
    p=sub.add_parser('udp-quic-like'); common(p); p.add_argument('--host',default='127.0.0.1'); p.add_argument('--port',type=int,default=443); p.add_argument('--count',type=int,default=1)
    p=sub.add_parser('batch'); common(p); p.add_argument('--matrix',type=Path,required=True)
    a=ap.parse_args()
    obs=[]
    if a.cmd=='http-get':
        for _ in range(a.count): obs.append(http_get(a.url,a.timeout))
    elif a.cmd=='tcp-connect':
        obs.append(tcp_connect(a.host,a.port,a.timeout,a.payload.encode('utf-8'),not a.no_read))
    elif a.cmd=='tls-handshake':
        obs.append(tls_handshake(a.host,a.port,a.server_name,a.timeout,a.alpn))
    elif a.cmd=='dns-udp':
        obs.append(dns_udp(a.server,a.port,a.qname,a.timeout,a.qtype))
    elif a.cmd=='udp-quic-like':
        obs.append(udp_quic_like(a.host,a.port,a.timeout,a.count))
    elif a.cmd=='batch':
        for sc in load_matrix(a.matrix): obs.append(run_scenario(sc,a.timeout))
    doc={'ok': all(o.ok for o in obs), 'observations':[asdict(o) for o in obs]}
    text=json.dumps(doc,indent=2,ensure_ascii=False)
    if a.json_out:
        a.json_out.parent.mkdir(parents=True,exist_ok=True)
        a.json_out.write_text(text,encoding='utf-8')
    print(text)
    sys.exit(0 if doc['ok'] else 1)
if __name__=='__main__': main()
