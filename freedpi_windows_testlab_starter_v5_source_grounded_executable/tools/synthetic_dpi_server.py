#!/usr/bin/env python3
"""
synthetic_dpi_server.py

Local, deterministic emulation of DPI/blocking symptoms for testing FreeDPI-Windows's
probe/classifier (core/src/probe/) and whitelist detector (core/src/detector/). This
is NOT a real DPI box — it produces reproducible network-level symptoms on 127.0.0.1
so probe/classifier/AutoTune logic can be exercised without a live ISP DPI.

Grounded in source:
  - core/src/detector/detector.rs (WhitelistDetector) distinguishes CanaryRole::
    Positive (must succeed) vs Negative (expected blocked under whitelist mode) —
    DROP_ALL_WHITELIST_MODE below emulates that by allowing "positive" domains and
    dropping everything else.
  - core/src/probe/{dns,http,tcp,tls,quic,tcp16,timing,ja4}_probe.rs each target a
    specific protocol layer, matching the block-mode list below one-to-one where
    a local emulation is feasible over plain sockets.

USAGE MODEL:
  This server must be pointed at by the FreeDPI-Windows test config — typically via
  a hosts-file override or a config.toml routing override pointing a fixed set of
  test domains at 127.0.0.1. This script does not modify the Windows hosts file or
  FreeDPI's config; that's the test harness's job (see run_dpi_probe_oracle.ps1,
  not yet delivered — wire it there).

LIMITATIONS (explicit, not hidden):
  - QUIC_UDP_DROP / QUIC_ICMP_UNREACHABLE_OR_EQUIVALENT: UDP drop is trivial (just
    don't respond); ICMP unreachable requires raw sockets / admin privileges on
    Windows and is only attempted if run elevated. Falls back to "drop silently" and
    logs a warning that the ICMP variant wasn't actually sent.
  - HTTP2_SPECIFIC_FAILURE: emulated as a TCP-level connection reset immediately
    after seeing an ALPN h2 attempt is NOT implemented (would require a real TLS
    stack to inspect ALPN) — this mode currently behaves identically to
    TCP_RST_AFTER_CLIENTHELLO and is flagged as a known simplification. A real
    implementation needs a minimal TLS record parser to distinguish ALPN=h2 from
    ALPN=http/1.1, which is out of scope for a first pass.
  - VOLUME_BASED_THROTTLE: implemented as a crude token-bucket rate limiter on the
    HTTP responder only; does not throttle raw TCP/UDP.
"""
import argparse
import http.server
import json
import socket
import ssl
import struct
import sys
import threading
import time
from dataclasses import dataclass, field

MODES = [
    "CLEAN_ALLOW", "DNS_NXDOMAIN_POISON", "DNS_WRONG_IP", "DNS_TIMEOUT",
    "TCP_CONNECT_TIMEOUT", "TCP_RST_AFTER_SYN", "TCP_RST_AFTER_CLIENTHELLO",
    "TLS_HANDSHAKE_TIMEOUT", "TLS_ALERT_AFTER_SNI", "HTTP_BLOCK_PAGE",
    "HTTP_403_BLOCK", "HTTP2_SPECIFIC_FAILURE", "QUIC_UDP_DROP",
    "QUIC_ICMP_UNREACHABLE_OR_EQUIVALENT", "SNI_BASED_BLOCK", "IP_BASED_BLOCK",
    "VOLUME_BASED_THROTTLE", "DROP_ALL_WHITELIST_MODE",
]

TLS_ALERT_HANDSHAKE_FAILURE = bytes.fromhex("1503010002022f")  # TLS alert: fatal, handshake_failure


@dataclass
class ServerState:
    mode: str = "CLEAN_ALLOW"
    lock: threading.Lock = field(default_factory=threading.Lock)
    positive_domains: set = field(default_factory=set)  # for DROP_ALL_WHITELIST_MODE
    request_log: list = field(default_factory=list)
    rate_bucket: dict = field(default_factory=dict)  # for VOLUME_BASED_THROTTLE

    def set_mode(self, mode: str):
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}, must be one of {MODES}")
        with self.lock:
            self.mode = mode

    def log(self, event: dict):
        event["ts"] = time.time()
        with self.lock:
            self.request_log.append(event)


def tcp_listener(state: ServerState, port: int, host: str = "127.0.0.1"):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(16)
    print(f"[tcp] listening on {host}:{port}", file=sys.stderr)

    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            return
        threading.Thread(target=handle_tcp_conn, args=(state, conn, addr), daemon=True).start()


def handle_tcp_conn(state: ServerState, conn: socket.socket, addr):
    mode = state.mode
    state.log({"layer": "tcp", "mode": mode, "peer": addr})
    try:
        if mode == "TCP_CONNECT_TIMEOUT":
            time.sleep(3600)  # hold the connection open, never respond
            return
        if mode in ("TCP_RST_AFTER_SYN",):
            _send_rst(conn)
            return
        if mode in ("TCP_RST_AFTER_CLIENTHELLO", "HTTP2_SPECIFIC_FAILURE"):
            try:
                conn.settimeout(5)
                data = conn.recv(4096)  # wait for ClientHello
            except socket.timeout:
                data = b""
            _send_rst(conn)
            return
        if mode == "TLS_HANDSHAKE_TIMEOUT":
            try:
                conn.settimeout(5)
                conn.recv(4096)
            except socket.timeout:
                pass
            time.sleep(3600)
            return
        if mode == "TLS_ALERT_AFTER_SNI":
            try:
                conn.settimeout(5)
                conn.recv(4096)
            except socket.timeout:
                pass
            try:
                conn.sendall(TLS_ALERT_HANDSHAKE_FAILURE)
            except OSError:
                pass
            conn.close()
            return
        if mode == "SNI_BASED_BLOCK":
            # Simplification: without a real TLS record parser this can't actually
            # inspect SNI. Behaves like TLS_ALERT_AFTER_SNI. A proper implementation
            # should parse the ClientHello extension list for server_name and only
            # block matching domains — flagged as a follow-up, not silently claimed.
            try:
                conn.settimeout(5)
                conn.recv(4096)
                conn.sendall(TLS_ALERT_HANDSHAKE_FAILURE)
            except OSError:
                pass
            conn.close()
            return
        if mode == "IP_BASED_BLOCK":
            _send_rst(conn)
            return
        if mode == "DROP_ALL_WHITELIST_MODE":
            # Whitelist-drop-all emulation for core/src/detector/detector.rs testing.
            # Without domain-level info at the raw TCP layer, this mode requires the
            # test harness to route "positive" canary domains to a DIFFERENT port
            # (or a different server instance in CLEAN_ALLOW mode) and only point
            # "negative" domains at this port/mode. Document this wiring requirement
            # in run_dpi_probe_oracle.ps1 rather than trying to fake it here.
            _send_rst(conn)
            return
        # CLEAN_ALLOW and anything unhandled falls through to a minimal echo/close
        conn.settimeout(2)
        try:
            conn.recv(4096)
        except socket.timeout:
            pass
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _send_rst(conn: socket.socket):
    """Force an RST instead of a graceful FIN by setting SO_LINGER(on, 0)."""
    try:
        conn.setsockopt(
            socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
        )
    except OSError:
        pass
    try:
        conn.close()
    except OSError:
        pass


class HttpModeHandler(http.server.BaseHTTPRequestHandler):
    state: ServerState = None  # injected by factory

    def _rate_limited(self) -> bool:
        bucket = self.state.rate_bucket.setdefault(self.client_address[0], {"tokens": 5, "ts": time.time()})
        now = time.time()
        elapsed = now - bucket["ts"]
        bucket["tokens"] = min(5, bucket["tokens"] + elapsed * 1)  # 1 token/sec refill
        bucket["ts"] = now
        if bucket["tokens"] < 1:
            return True
        bucket["tokens"] -= 1
        return False

    def do_GET(self):
        mode = self.state.mode
        self.state.log({"layer": "http", "mode": mode, "path": self.path, "peer": self.client_address})

        if mode == "HTTP_BLOCK_PAGE":
            body = b"<html><body>Access to this resource is restricted.</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if mode == "HTTP_403_BLOCK":
            body = b"Forbidden"
            self.send_response(403)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if mode == "VOLUME_BASED_THROTTLE":
            if self._rate_limited():
                self.send_response(429)
                self.send_header("Retry-After", "1")
                self.end_headers()
                return
        body = b"OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # suppress default stderr spam; use state.request_log instead


def http_listener(state: ServerState, port: int, host: str = "127.0.0.1"):
    handler = type("BoundHttpModeHandler", (HttpModeHandler,), {"state": state})
    srv = http.server.ThreadingHTTPServer((host, port), handler)
    print(f"[http] listening on {host}:{port}", file=sys.stderr)
    srv.serve_forever()


def udp_listener(state: ServerState, port: int, host: str = "127.0.0.1"):
    """Handles DNS_* modes (crude DNS responder) and QUIC_UDP_DROP (never responds)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"[udp] listening on {host}:{port}", file=sys.stderr)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except OSError:
            return
        mode = state.mode
        state.log({"layer": "udp", "mode": mode, "peer": addr, "len": len(data)})

        if mode == "QUIC_UDP_DROP":
            continue  # silently drop, no response
        if mode == "QUIC_ICMP_UNREACHABLE_OR_EQUIVALENT":
            # Sending a real ICMP port-unreachable requires a raw socket and admin
            # rights; not attempted here. Document that this mode currently behaves
            # like QUIC_UDP_DROP until raw-socket support is added.
            print("WARNING: QUIC_ICMP_UNREACHABLE_OR_EQUIVALENT requested but raw "
                  "ICMP send not implemented; behaving as QUIC_UDP_DROP", file=sys.stderr)
            continue
        if mode in ("DNS_NXDOMAIN_POISON", "DNS_WRONG_IP", "DNS_TIMEOUT"):
            _handle_dns(sock, data, addr, mode)
            continue
        # default: minimal DNS success response for CLEAN_ALLOW-equivalent testing
        _handle_dns(sock, data, addr, "CLEAN_ALLOW")


def _handle_dns(sock: socket.socket, data: bytes, addr, mode: str):
    if mode == "DNS_TIMEOUT":
        return  # no response at all
    if len(data) < 12:
        return
    txid = data[0:2]
    # Build a minimal response reusing the question section verbatim.
    try:
        qdcount = struct.unpack(">H", data[4:6])[0]
        if qdcount != 1:
            return
        # Skip header (12 bytes), copy question section as-is
        idx = 12
        while data[idx] != 0:
            idx += data[idx] + 1
        qname_end = idx + 1 + 4  # null byte + qtype(2) + qclass(2)
        question = data[12:qname_end]
    except (IndexError, struct.error):
        return

    if mode == "DNS_NXDOMAIN_POISON":
        flags = struct.pack(">H", 0x8183)  # QR=1, RCODE=3 NXDOMAIN
        header = txid + flags + struct.pack(">HHHH", 1, 0, 0, 0)
        sock.sendto(header + question, addr)
        return

    if mode == "DNS_WRONG_IP":
        flags = struct.pack(">H", 0x8180)  # QR=1, RCODE=0
        header = txid + flags + struct.pack(">HHHH", 1, 1, 0, 0)
        answer = (
            b"\xc0\x0c"  # name ptr to question
            + struct.pack(">HHIH", 1, 1, 60, 4)  # TYPE A, CLASS IN, TTL 60, RDLENGTH 4
            + socket.inet_aton("198.51.100.1")  # TEST-NET-2, deliberately wrong/unroutable
        )
        sock.sendto(header + question + answer, addr)
        return

    # CLEAN_ALLOW fallback: resolve to localhost so downstream traffic lands here too
    flags = struct.pack(">H", 0x8180)
    header = txid + flags + struct.pack(">HHHH", 1, 1, 0, 0)
    answer = (
        b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("127.0.0.1")
    )
    sock.sendto(header + question + answer, addr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--tcp-port", type=int, default=8443)
    ap.add_argument("--dns-port", type=int, default=8053)
    ap.add_argument("--mode", choices=MODES, default="CLEAN_ALLOW")
    ap.add_argument("--control-port", type=int, default=8090,
                     help="Simple HTTP control endpoint: POST /mode {\"mode\": \"...\"} "
                          "and GET /log to retrieve state.request_log as JSON")
    args = ap.parse_args()

    state = ServerState(mode=args.mode)

    threading.Thread(target=tcp_listener, args=(state, args.tcp_port), daemon=True).start()
    threading.Thread(target=http_listener, args=(state, args.http_port), daemon=True).start()
    threading.Thread(target=udp_listener, args=(state, args.dns_port), daemon=True).start()

    class ControlHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path == "/mode":
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                try:
                    state.set_mode(body["mode"])
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"ok": true}')
                except (KeyError, ValueError) as e:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(json.dumps({"ok": False, "error": str(e)}).encode())
                return
            self.send_response(404)
            self.end_headers()

        def do_GET(self):
            if self.path == "/log":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(state.request_log).encode())
                return
            if self.path == "/mode":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"mode": state.mode}).encode())
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, fmt, *args):
            pass

    print(f"[control] listening on 127.0.0.1:{args.control_port} "
          f"(POST /mode, GET /mode, GET /log)", file=sys.stderr)
    print(f"Initial mode: {state.mode}", file=sys.stderr)
    http.server.ThreadingHTTPServer(("127.0.0.1", args.control_port), ControlHandler).serve_forever()


if __name__ == "__main__":
    main()
