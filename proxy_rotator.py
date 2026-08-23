#!/usr/bin/env python3
"""
Local rotating HTTP/HTTPS proxy.

Reads proxies from proxies.txt (one per line: scheme://user:pass@host:port),
listens on a local port, and forwards each connection through a rotating proxy.

Usage:
    python proxy_rotator.py                     # default port 8099
    python proxy_rotator.py --port 9090         # custom port
    python proxy_rotator.py --proxies my.txt    # custom proxy list
    python proxy_rotator.py --ban-threshold 3   # ban after N failures (default 5)

The proxies are rotated in round-robin order. Proxies that fail are temporarily
banned (exponential backoff, max 5 min). When all proxies are banned, the
rotator waits until the oldest ban expires.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import secrets
import socket
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("proxy-rotator")

ROOT = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Proxy pool
# ---------------------------------------------------------------------------

@dataclass
class ProxyEntry:
    raw: str
    host: str
    port: int
    scheme: str
    username: str = ""
    password: str = ""
    fail_count: int = 0
    ban_until: float = 0.0  # timestamp
    total_requests: int = 0
    total_failures: int = 0

    @property
    def is_banned(self) -> bool:
        return time.time() < self.ban_until

    @property
    def display(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def record_failure(self, ban_threshold: int) -> None:
        self.fail_count += 1
        self.total_failures += 1
        if self.fail_count >= ban_threshold:
            # exponential backoff: 30s, 60s, 120s, 300s (max 5 min)
            delay = min(30 * (2 ** (self.fail_count - ban_threshold)), 300)
            self.ban_until = time.time() + delay
            log.warning(f"BANNED {self.display} for {int(delay)}s (fail#{self.fail_count})")

    def record_success(self) -> None:
        self.fail_count = 0
        self.ban_until = 0.0
        self.total_requests += 1

    def short_info(self) -> str:
        status = f"BANNED {int(self.ban_until - time.time())}s" if self.is_banned else "OK"
        return f"{self.display} [{status}] req={self.total_requests} fail={self.total_failures}"


class ProxyPool:
    def __init__(self, proxies_file: str | Path, ban_threshold: int = 5):
        self._lock = threading.Lock()
        self._entries: list[ProxyEntry] = []
        self._index = 0
        self._ban_threshold = ban_threshold
        self._proxies_file = Path(proxies_file)
        self._last_used: Optional[ProxyEntry] = None
        self._load(proxies_file)

    def _load(self, path: str | Path) -> None:
        p = Path(path)
        if not p.is_file():
            log.error(f"proxy file not found: {p}")
            return
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entry = self._parse(line)
            if entry:
                self._entries.append(entry)
        log.info(f"loaded {len(self._entries)} proxies from {p.name}")

    @staticmethod
    def _parse(raw: str) -> Optional[ProxyEntry]:
        try:
            p = urlsplit(raw)
            if not p.hostname:
                return None
            scheme = (p.scheme or "http").lower()
            if scheme in ("socks", "socks5h"):
                scheme = "socks5"
            return ProxyEntry(
                raw=raw,
                host=p.hostname,
                port=p.port or (1080 if scheme.startswith("socks") else 80),
                scheme=scheme,
                username=p.username or "",
                password=p.password or "",
            )
        except Exception:
            return None

    def next(self) -> Optional[ProxyEntry]:
        """Get the next non-banned proxy (round-robin)."""
        with self._lock:
            if not self._entries:
                return None
            n = len(self._entries)
            for _ in range(n):
                entry = self._entries[self._index % n]
                self._index += 1
                if not entry.is_banned:
                    self._last_used = entry
                    return entry
            # all banned — return the one whose ban expires soonest
            earliest = min(self._entries, key=lambda e: e.ban_until)
            wait = earliest.ban_until - time.time()
            if wait > 0:
                log.info(f"all proxies banned, waiting {int(wait)}s for {earliest.display}")
                time.sleep(min(wait + 0.5, 60))
            self._last_used = earliest
            return earliest

    def get_raw(self) -> str:
        """Get the raw URL of the next proxy (for upstream CONNECT)."""
        entry = self.next()
        return entry.raw if entry else ""

    def status(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "host": e.host,
                    "port": e.port,
                    "scheme": e.scheme,
                    "banned": e.is_banned,
                    "ban_remaining": max(0, int(e.ban_until - time.time())),
                    "requests": e.total_requests,
                    "failures": e.total_failures,
                }
                for e in self._entries
            ]

    def count(self) -> int:
        return len(self._entries)

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for e in self._entries if not e.is_banned)

    def on_success(self, entry: ProxyEntry) -> None:
        with self._lock:
            entry.record_success()

    def on_failure(self, entry: ProxyEntry) -> None:
        with self._lock:
            entry.record_failure(self._ban_threshold)

    def disable_last_used(self) -> dict:
        """Permanently disable the last-used proxy: comment it out in the file and
        remove from the active pool.  Returns a status dict."""
        with self._lock:
            entry = self._last_used
            if not entry:
                return {"ok": False, "error": "no proxy has been used yet"}
            raw = entry.raw
            host_port = f"{entry.host}:{entry.port}"
            # remove from pool
            idx = next((i for i, e in enumerate(self._entries) if e is entry), None)
            if idx is not None:
                self._entries.pop(idx)
                if self._index >= len(self._entries):
                    self._index = 0
            self._last_used = None

        # comment out in file
        try:
            lines = self._proxies_file.read_text(encoding="utf-8").splitlines(keepends=True)
            commented = 0
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped == raw or stripped.rstrip("\r\n") == raw:
                    if not stripped.startswith("#"):
                        lines[i] = f"# {stripped}"
                        commented += 1
            if commented:
                self._proxies_file.write_text("".join(lines), encoding="utf-8")
                log.warning(f"PERMANENTLY DISABLED: {host_port} (commented in proxies.txt)")
        except Exception as exc:
            log.error(f"failed to comment out proxy in file: {exc}")

        return {"ok": True, "disabled": host_port, "remaining": len(self._entries)}

    def disable_by_host_port(self, host: str, port: int) -> dict:
        """Disable a specific proxy by host:port.  If no entry matches, try
        commenting all lines that resolve to that host:port."""
        entry = None
        with self._lock:
            entry = next((e for e in self._entries if e.host == host and e.port == port), None)
        if entry:
            with self._lock:
                idx = next((i for i, e in enumerate(self._entries) if e is entry), None)
                if idx is not None:
                    self._entries.pop(idx)
                    if self._index >= len(self._entries):
                        self._index = 0
            raw = entry.raw
        else:
            raw = f"://{host}:{port}"

        try:
            lines = self._proxies_file.read_text(encoding="utf-8").splitlines(keepends=True)
            commented = 0
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("#") or not stripped:
                    continue
                if host in stripped and f":{port}" in stripped:
                    lines[i] = f"# {stripped}"
                    commented += 1
            if commented:
                self._proxies_file.write_text("".join(lines), encoding="utf-8")
                log.warning(f"PERMANENTLY DISABLED: {host}:{port} ({commented} lines commented)")
        except Exception as exc:
            log.error(f"failed to comment out proxy: {exc}")

        return {"ok": True, "disabled": f"{host}:{port}", "commented_lines": commented, "remaining": len(self._entries)}

    @property
    def last_used_info(self) -> Optional[dict]:
        """Info about the last-used proxy."""
        with self._lock:
            e = self._last_used
            if not e:
                return None
            return {"host": e.host, "port": e.port, "raw": e.raw}


# ---------------------------------------------------------------------------
# Local proxy handler
# ---------------------------------------------------------------------------

_pool: Optional[ProxyPool] = None

class ProxyHandler:
    """Handle one local client connection by relaying through an upstream proxy."""

    def __init__(self, client: socket.socket, addr: tuple, pool: ProxyPool):
        self.client = client
        self.addr = addr
        self.pool = pool
        self._entry: Optional[ProxyEntry] = None

    def run(self) -> None:
        try:
            self.client.settimeout(30)
            first = self.client.recv(65536)
            if not first:
                return

            # Pick a proxy
            self._entry = self.pool.next()
            if not self._entry:
                self.client.sendall(b"HTTP/1.1 503 No proxies available\r\n\r\n")
                return

            if first[:7] == b"CONNECT":
                self._handle_connect(first)
            else:
                self._handle_http(first)
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception as exc:
            log.debug(f"handler error: {exc}")
        finally:
            try:
                self.client.close()
            except OSError:
                pass

    def _connect_upstream(self) -> socket.socket:
        """Connect to the selected upstream proxy."""
        entry = self._entry
        s = socket.create_connection((entry.host, entry.port), timeout=15)

        if entry.scheme.startswith("socks"):
            self._socks5_handshake(s, entry)
        elif entry.username:
            # HTTP proxy with auth — inject Proxy-Authorization
            pass  # handled per-request below
        return s

    def _socks5_handshake(self, s: socket.socket, entry: ProxyEntry) -> None:
        """SOCKS5 greeting + optional user/pass auth."""
        if entry.username:
            s.sendall(b"\x05\x01\x02")  # support user/pass auth
        else:
            s.sendall(b"\x05\x01\x00")  # no auth
        resp = s.recv(2)
        if len(resp) < 2 or resp[0] != 5:
            raise OSError(f"socks5: bad greeting {resp!r}")

        if resp[1] == 0x02 and entry.username:
            user = entry.username.encode()
            pwd = entry.password.encode()
            s.sendall(bytes([1, len(user)]) + user + bytes([len(pwd)]) + pwd)
            resp = s.recv(2)
            if len(resp) < 2 or resp[1] != 0:
                raise OSError("socks5: auth rejected")
        elif resp[1] != 0x00:
            raise OSError(f"socks5: no acceptable method (got {resp[1]})")

    def _socks5_connect(self, s: socket.socket, host: str, port: int) -> None:
        """SOCKS5 CONNECT with hostname (remote DNS)."""
        h = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + port.to_bytes(2, "big"))
        resp = s.recv(10)
        if len(resp) < 2 or resp[1] != 0:
            raise OSError(f"socks5: connect failed code={resp[1] if len(resp) > 1 else '?'}")

    def _inject_auth(self, data: bytes) -> bytes:
        """Add Proxy-Authorization header for HTTP upstream proxies."""
        entry = self._entry
        if not entry or not entry.username:
            return data
        token = base64.b64encode(f"{entry.username}:{entry.password}".encode()).decode()
        head, sep, rest = data.partition(b"\r\n\r\n")
        if not sep:
            return data
        lines = head.split(b"\r\n")
        out = [lines[0]]
        for ln in lines[1:]:
            if ln.lower().startswith(b"proxy-authorization:"):
                continue
            out.append(ln)
        out.append(f"Proxy-Authorization: Basic {token}".encode())
        return b"\r\n".join(out) + b"\r\n\r\n" + rest

    def _relay(self, src: socket.socket, dst: socket.socket, timeout: float = 180) -> None:
        """Bidirectional relay."""
        src.settimeout(timeout)
        dst.settimeout(timeout)

        def pump(a: socket.socket, b: socket.socket):
            try:
                while True:
                    data = a.recv(65536)
                    if not data:
                        break
                    b.sendall(data)
            except OSError:
                pass
            finally:
                for sock in (a, b):
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        t1 = threading.Thread(target=pump, args=(src, dst), daemon=True)
        t2 = threading.Thread(target=pump, args=(dst, src), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    def _handle_connect(self, first: bytes) -> None:
        """Handle HTTPS CONNECT tunnel."""
        line = first.split(b"\r\n", 1)[0]
        hostport = line.split()[1].decode()
        host, _, port_s = hostport.rpartition(":")
        port = int(port_s or "443")

        entry = self._entry
        try:
            upstream = self._connect_upstream()

            if entry.scheme.startswith("socks"):
                self._socks5_connect(upstream, host, port)
                self.client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            else:
                # HTTP upstream: forward CONNECT with auth
                authed = self._inject_auth(first)
                upstream.sendall(authed)
                # Read upstream's reply
                reply = b""
                while b"\r\n\r\n" not in reply and len(reply) < 8192:
                    chunk = upstream.recv(4096)
                    if not chunk:
                        break
                    reply += chunk
                if not reply:
                    reply = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
                self.client.sendall(reply)

            self.pool.on_success(entry)
            self._relay(self.client, upstream)
        except Exception as exc:
            self.pool.on_failure(entry)
            log.debug(f"CONNECT failed via {entry.display}: {exc}")
            try:
                self.client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except OSError:
                pass

    def _handle_http(self, first: bytes) -> None:
        """Handle plain HTTP request."""
        entry = self._entry
        try:
            upstream = self._connect_upstream()
            upstream.sendall(self._inject_auth(first))
            self.pool.on_success(entry)
            self._relay(self.client, upstream)
        except Exception as exc:
            self.pool.on_failure(entry)
            log.debug(f"HTTP failed via {entry.display}: {exc}")


# ---------------------------------------------------------------------------
# Status server (optional: localhost JSON endpoint)
# ---------------------------------------------------------------------------

def _status_server(port: int, pool: ProxyPool) -> None:
    """Tiny HTTP server that returns pool status as JSON."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(20)
    srv.settimeout(1.0)

    while True:
        try:
            client, _ = srv.accept()
            client.settimeout(5)
            data = client.recv(4096)
            if b"GET /status" in data:
                body = json.dumps({
                    "total": pool.count(),
                    "active": pool.active_count(),
                    "last_used": pool.last_used_info,
                    "proxies": pool.status(),
                }).encode()
                resp = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode() + body
            elif b"POST /disable" in data:
                # Parse JSON body
                try:
                    body_start = data.find(b"\r\n\r\n")
                    body_bytes = data[body_start + 4:] if body_start >= 0 else b""
                    req = json.loads(body_bytes) if body_bytes else {}
                except Exception:
                    req = {}
                # disable last used or specific host:port
                if "host" in req and "port" in req:
                    result = pool.disable_by_host_port(req["host"], int(req["port"]))
                else:
                    result = pool.disable_last_used()
                body = json.dumps(result).encode()
                resp = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode() + body
            elif b"GET /health" in data:
                body = b'{"ok":true,"service":"proxy-rotator"}'
                resp = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode() + body
            else:
                resp = b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n"
            client.sendall(resp)
            client.close()
        except socket.timeout:
            continue
        except OSError:
            break


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    global _pool

    ap = argparse.ArgumentParser(description="Local rotating proxy server")
    ap.add_argument("--port", type=int, default=8099, help="local listen port (default 8099)")
    ap.add_argument("--status-port", type=int, default=8100, help="status HTTP port (default 8100)")
    ap.add_argument("--proxies", default=str(ROOT / "proxies.txt"), help="proxy list file")
    ap.add_argument("--ban-threshold", type=int, default=5, help="failures before ban (default 5)")
    ap.add_argument("--verbose", action="store_true", help="debug logging")
    args = ap.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    _pool = ProxyPool(args.proxies, ban_threshold=args.ban_threshold)
    if _pool.count() == 0:
        log.error("no proxies loaded — check your proxy file")
        return 1

    # Start status server in background
    status_thread = threading.Thread(target=_status_server, args=(args.status_port, _pool), daemon=True)
    status_thread.start()
    log.info(f"status server: http://127.0.0.1:{args.status_port}/status")

    # Main proxy server
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", args.port))
    except OSError as exc:
        log.error(f"cannot bind port {args.port}: {exc}")
        return 1
    srv.listen(100)
    log.info(f"rotating proxy listening on http://127.0.0.1:{args.port}")
    log.info(f"pool: {_pool.count()} proxies, ban threshold={args.ban_threshold}")

    try:
        while True:
            try:
                client, addr = srv.accept()
                handler = ProxyHandler(client, addr, _pool)
                threading.Thread(target=handler.run, daemon=True).start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        srv.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
