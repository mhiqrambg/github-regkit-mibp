"""GitHub sign-up automation driven by Camoufox (Firefox anti-detect) + Litensi mail."""
from __future__ import annotations

import json
import hashlib
import logging
import os
import socket
import socketserver
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

from camoufox.sync_api import Camoufox
import requests

from .config import Config
from .litensi import LitensiClient, LitensiError
from .mailcx import MailCxClient, MailCxError
from .profiles import (
    generate_password,
    generate_username,
    parse_public_profile,
    username_from_email,
)

ROOT = Path(__file__).resolve().parent.parent
ACCOUNTS_DIR = ROOT / "accounts"
RECOVERY_DIR = ACCOUNTS_DIR / "recovery"


def _save_recovery_per_account(email: str, recovery: str, log) -> None:
    """Store one account's multiline recovery codes in accounts/recovery/."""
    if not recovery:
        return
    try:
        RECOVERY_DIR.mkdir(parents=True, exist_ok=True)
        key = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
        (RECOVERY_DIR / f"{key}.txt").write_text(recovery.strip() + "\n", encoding="utf-8")
        log(f"[*] recovery codes saved for {email}")
    except Exception as exc:
        log(f"[i] recovery codes write failed: {exc}")

_EMAIL_INPUTS = ["#email", "input[name='email']", "input[type='email']"]
_PASSWORD_INPUTS = ["#password", "input[name='password']"]
_USERNAME_INPUTS = ["#login", "input[name='login']"]
_OTP_INPUTS = [
    "#otp",
    "input[name='otp']",
    "input[autocomplete='one-time-code']",
    "#launch-code-0",  # verify page: 8 single-digit boxes launch-code-0..7
]
# The main signup form (NOT the Google/Apple OAuth forms which live in their own <form> tags)
_SIGNUP_FORM = "form[action*='signup']"
_SUBMIT_SELECTORS = [f"{_SIGNUP_FORM} button[type='submit']", "#submit", "button[type='submit']"]


class SignupError(RuntimeError):
    pass


class SignupBlocked(SignupError):
    pass


class RegistrationCancelled(SignupError):
    pass


class GitHubRateLimited(SignupError):
    pass


_DATADOME_HARD_BLOCK_MARKERS = (
    "access is temporarily restricted",
    "we detected unusual activity",
    "your access is restricted",
    "you have been temporarily blocked",
    # Indonesian localization of the DataDome block page
    "akses dibatasi untuk sementara",
    "kami mendeteksi aktivitas yang tidak biasa",
    "ada robot di jaringan",
)

_RATE_LIMIT_MARKERS = (
    "secondary rate limit",
    "too many requests",
    "you have exceeded a secondary rate limit",
    "please wait a few minutes before you try again",
)


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _raise_if_cancelled(stop) -> None:
    if stop and stop():
        raise RegistrationCancelled("stop requested")


def _sleep_with_cancel(seconds: float, stop=None) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        _raise_if_cancelled(stop)
        time.sleep(min(0.25, deadline - time.time()))


def silence_playwright_noise() -> None:
    """Suppress the asyncio 'Task exception was never retrieved' spam.

    Playwright leaves in-flight Channel.send tasks behind when the browser is
    closed mid-operation; asyncio then dumps a TargetClosedError traceback for
    each of them. Harmless noise — filter it at the logging level.
    """
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)


def _parse_proxy(url: str) -> Optional[dict]:
    """'http(s)/socks5(h)://user:pass@host:port' -> Camoufox proxy dict, or None.

    Scheme normalization (Playwright accepts only these):
      socks://   -> socks5://   (bare 'socks' is rejected by Firefox)
      socks5h:// -> socks5://   ('h' variant is a curl/requests-only notation;
                                 Firefox resolves DNS remotely by default)
    """
    url = (url or "").strip()
    if not url:
        return None
    p = urlsplit(url)
    if not p.hostname:
        raise SignupError(f"invalid proxy url: {url}")
    scheme = (p.scheme or "http").lower()
    if scheme in ("socks", "socks5h"):
        scheme = "socks5"
    if scheme not in ("http", "https", "socks4", "socks5"):
        raise SignupError(f"unsupported proxy scheme: {p.scheme}:// (use http/socks5)")
    port = p.port or (1080 if scheme.startswith("socks") else (443 if scheme == "https" else 80))
    proxy = {"server": f"{scheme}://{p.hostname}:{port}"}
    if p.username:
        proxy["username"] = p.username
        proxy["password"] = p.password or ""
    return proxy


def _proxy_is_socks(proxy: Optional[dict]) -> bool:
    return bool(proxy) and str(proxy.get("server", "")).startswith("socks")


def _socks_exit_ip(url: str, timeout: int = 12) -> str:
    """Resolve the proxy exit IP using the 'socks5h://' scheme (remote DNS).

    DataImpulse (and similar gateways) reject IP-based connections under a
    'ruleset' when the client resolves DNS locally (plain socks5://). The
    requests-based geoip probe inside Camoufox uses plain socks5 and dies with
    '0x02: Connection not allowed by ruleset' — so we look the exit IP up
    ourselves over socks5h and hand it to Camoufox via geoip=<ip>.
    """
    import requests as _requests

    p = urlsplit(url.strip())
    scheme = "socks5h" if (p.scheme or "socks").lower().startswith("socks") else (p.scheme or "http")
    auth = f"{p.username}:{p.password}@" if p.username else ""
    port = p.port or 1080
    proxies = {"http": f"{scheme}://{auth}{p.hostname}:{port}",
               "https": f"{scheme}://{auth}{p.hostname}:{port}"}
    last_exc: Exception | None = None
    # sticky ports can take a few seconds to warm up (allocate the IP) — retry
    for attempt in range(2):
        for check_url in ("https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.co/ip"):
            try:
                resp = _requests.get(check_url, proxies=proxies, timeout=20)
                ip = (resp.text or "").strip()
                if resp.ok and ip:
                    return ip
            except Exception as exc:
                last_exc = exc
        if attempt == 0:
            time.sleep(3)  # give the sticky session a moment to warm up
    raise SignupError(f"socks exit-IP lookup failed: {last_exc}")


# ---------------------------------------------------------------------------
# Sticky proxy session
#
# Residential gateways such as DataImpulse rotate the exit IP on EVERY TCP
# connection by default (rotating ports 823/824). A browser opens dozens of
# parallel connections — mid-session IP changes are an instant DataDome flag
# ("same cookie, different countries within seconds").
#
# Fix: use a STICKY port instead. DataImpulse assigns ports 10000–20000 for
# sticky SOCKS5 — all connections through the same port exit through the SAME
# IP for the session lifetime (~30 min default).
# ---------------------------------------------------------------------------

_sticky_suffix: Optional[str] = None
_last_exit_ip: Optional[str] = None


def _ensure_sticky_proxy(url: str, log=None) -> str:
    """Switch a rotating DataImpulse endpoint to a sticky one.

    DataImpulse docs: rotating = port 823 (HTTP) / 824 (SOCKS5); sticky =
    ports 10000-20000. We pick a random sticky port per process so each job
    gets a fresh stable IP. The port is deterministic within the process.
    """
    p = urlsplit(url.strip())
    port = p.port or 0
    # only switch known rotating ports
    if port in (823, 824):
        global _sticky_suffix
        if _sticky_suffix is None:
            import secrets as _secrets

            _sticky_suffix = str(10000 + int(_secrets.token_hex(4), 16) % 10001)
            if log:
                log(f"[*] sticky proxy port: {_sticky_suffix} (IP stabil ~30 menit, DataImpulse)")
        scheme = (p.scheme or "socks5").lower()
        if scheme in ("socks", "socks5h"):
            scheme = "socks5"
        auth = f"{p.username}:{p.password}@" if p.username else ""
        return f"{scheme}://{auth}{p.hostname}:{_sticky_suffix}"
    return url.strip()  # already sticky or non-DataImpulse — untouched


# ---------------------------------------------------------------------------
# Local auth proxy bridge
#
# Firefox does not support authenticated SOCKS5 proxies ("Browser does not
# support socks5 proxy authentication") and many gateways reject locally
# resolved DNS (socks5://). The bridge listens as a plain local HTTP proxy
# (no auth — Firefox loves that) and relays CONNECT/GET traffic to the
# upstream gateway with the credentials injected, resolving DNS remotely.
# Same pattern as LocalAuthProxyBridge in grok-regkit.
# ---------------------------------------------------------------------------

_UPSTREAM: dict = {}


class _AuthBridgeHandler(socketserver.BaseRequestHandler):
    def _relay(self, src: socket.socket, dst: socket.socket, timeout: float = 180.0) -> None:
        """Bidirectional relay using two pump threads (blocking one-way relay
        deadlocks TLS: the handshake needs simultaneous both-direction I/O)."""
        src.settimeout(timeout)
        dst.settimeout(timeout)

        def pump(a: socket.socket, b: socket.socket) -> None:
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

    def _connect_upstream(self) -> socket.socket:
        s = socket.create_connection((_UPSTREAM["host"], _UPSTREAM["port"]), timeout=20)
        if _UPSTREAM["socks"]:
            # minimal SOCKS5 handshake with remote DNS (ATYP=0x03 hostname)
            s.sendall(b"\x05\x01\x02")  # greet: support user/pass auth
            resp = s.recv(2)
            if len(resp) < 2 or resp[0] != 5:
                raise OSError("socks5: bad greeting")
            if resp[1] == 0x02:
                user = _UPSTREAM["user"].encode()
                pwd = _UPSTREAM["pass"].encode()
                s.sendall(bytes([1, len(user)]) + user + bytes([len(pwd)]) + pwd)
                resp = s.recv(2)
                if len(resp) < 2 or resp[1] != 0:
                    raise OSError("socks5: auth rejected")
            elif resp[1] != 0x00:
                raise OSError("socks5: no acceptable auth method")
        return s

    def _socks5_connect_remote(self, s: socket.socket, host: str, port: int) -> None:
        """SOCKS5 CONNECT with hostname (ATYP=0x03) so DNS resolves at the gateway."""
        h = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + port.to_bytes(2, "big"))
        resp = s.recv(10)
        if len(resp) < 2 or resp[1] != 0:
            raise OSError(f"socks5: connect failed code={resp[1] if len(resp) > 1 else '?'}")

    def _inject_auth_header(self, data: bytes) -> bytes:
        """Rewrite/add 'Proxy-Authorization: Basic ...' on the first request."""
        if not _UPSTREAM.get("user"):
            return data
        import base64

        token = base64.b64encode(f"{_UPSTREAM['user']}:{_UPSTREAM['pass']}".encode()).decode()
        head, sep, rest = data.partition(b"\r\n\r\n")
        if not sep:
            return data
        lines = head.split(b"\r\n")
        out = [lines[0]]
        for ln in lines[1:]:
            if ln.lower().startswith(b"proxy-authorization:"):
                continue  # drop existing
            out.append(ln)
        out.append(f"Proxy-Authorization: Basic {token}".encode())
        return b"\r\n".join(out) + b"\r\n\r\n" + rest

    def handle(self) -> None:
        try:
            self.request.settimeout(20)
            first = self.request.recv(65536)
            if not first:
                return
            if first[:7] == b"CONNECT":
                # --- HTTPS tunnel ---
                line = first.split(b"\r\n", 1)[0]
                hostport = line.split()[1].decode()
                host, _, port_s = hostport.rpartition(":")
                port = int(port_s or "443")
                upstream = self._connect_upstream()
                if _UPSTREAM["socks"]:
                    # SOCKS5 CONNECT with remote DNS, then tell the browser the
                    # tunnel is up — do NOT wait for upstream data (deadlock:
                    # upstream waits for the browser's TLS ClientHello).
                    self._socks5_connect_remote(upstream, host, port)
                    self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                else:
                    # HTTP upstream: forward CONNECT with auth injected, relay
                    # the gateway's own 2xx reply to the browser
                    authed = self._inject_auth_header(first)
                    upstream.sendall(authed)
                    reply = self._wait_http_connect_reply(upstream)
                    self.request.sendall(reply)
                self._relay(self.request, upstream)
            else:
                # --- plain HTTP: forward the full request with auth injected ---
                upstream = self._connect_upstream()
                upstream.sendall(self._inject_auth_header(first))
                self._relay(self.request, upstream)
        except OSError:
            pass
        finally:
            try:
                self.request.close()
            except OSError:
                pass

    @staticmethod
    def _wait_http_connect_reply(upstream: socket.socket, timeout: float = 20.0) -> bytes:
        """Read the upstream HTTP proxy's CONNECT reply (up to the blank line)."""
        upstream.settimeout(timeout)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 8192:
            chunk = upstream.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf or b"HTTP/1.1 502 Bad Gateway\r\n\r\n"


class LocalAuthProxyBridge:
    """Run a local no-auth HTTP proxy that forwards to an authed upstream.

    Use for SOCKS5-with-auth upstreams (Firefox can't authenticate to SOCKS5)
    or HTTP upstreams behind DataDome-style rulesets. DNS for CONNECT is
    resolved at the gateway (hostname-based SOCKS5 ATYP=0x03).
    """

    def __init__(self, proxy_url: str):
        p = urlsplit(proxy_url.strip())
        scheme = (p.scheme or "http").lower()
        if scheme in ("socks", "socks5", "socks5h"):
            scheme = "socks5"
        if not p.hostname:
            raise SignupError(f"invalid proxy url for bridge: {proxy_url}")
        self._upstream = {
            "host": p.hostname,
            "port": p.port or (1080 if scheme == "socks5" else 8080),
            "user": p.username or "",
            "pass": p.password or "",
            "socks": scheme == "socks5",
        }
        self._server: Optional[socketserver.ThreadingTCPServer] = None
        self.port: Optional[int] = None

    def start(self) -> int:
        global _UPSTREAM
        _UPSTREAM = self._upstream
        for attempt in range(20):
            candidate = 20000 + (os.getpid() % 10000) + attempt * 7
            try:
                self._server = socketserver.ThreadingTCPServer(
                    ("127.0.0.1", candidate), _AuthBridgeHandler
                )
                self._server.daemon_threads = True
                self.port = candidate
                threading.Thread(target=self._server.serve_forever, daemon=True).start()
                return candidate
            except OSError:
                continue
        raise SignupError("local auth proxy bridge: no free port found")

    def stop(self) -> None:
        if self._server:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None

    def browser_proxy(self) -> dict:
        """Playwright proxy dict pointing at the local bridge (no auth)."""
        return {"server": f"http://127.0.0.1:{self.port}"}


_bridge: Optional[LocalAuthProxyBridge] = None


def _stop_proxy_bridge() -> None:
    global _bridge
    if _bridge is not None:
        _bridge.stop()
        _bridge = None


def _rotate_sticky_proxy() -> None:
    """Discard a blocked DataImpulse sticky port and allocate a new one."""
    global _sticky_suffix, _last_exit_ip
    _stop_proxy_bridge()
    _sticky_suffix = None
    _last_exit_ip = None


def _disable_blocked_proxy(log) -> None:
    """Tell the proxy rotator to permanently disable the current upstream proxy.

    POST to http://127.0.0.1:8100/disable — the rotator comments out the proxy
    in proxies.txt so it's never used again.
    """
    try:
        import urllib.request
        req = urllib.request.Request(
            "http://127.0.0.1:8100/disable",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=5)
        data = json.loads(resp.read())
        if data.get("ok"):
            log(f"[!] permanently disabled proxy: {data.get('disabled')} ({data.get('remaining')} remaining)")
        else:
            log(f"[i] proxy disable: {data}")
    except Exception as exc:
        log(f"[i] could not disable proxy via rotator: {exc}")


def _proxy_needs_bridge(proxy: Optional[dict]) -> bool:
    """Firefox rejects authed SOCKS5; bridge it locally."""
    return bool(proxy) and str(proxy.get("server", "")).startswith("socks") and proxy.get("username")


def _page_text(page) -> str:
    try:
        return page.locator("body").inner_text(timeout=3000)
    except Exception:
        return ""


def _first(page, selectors: list[str], visible: bool = False):
    for sel in selectors:
        loc = page.locator(sel).first
        try:
            if loc.count() == 0:
                continue
            if not visible or loc.is_visible():
                return loc
        except Exception:
            continue
    raise SignupError(f"no visible element matching {selectors}")


def _wait_step(page, selectors: list[str], label: str, timeout: int = 30) -> None:
    try:
        page.wait_for_selector(", ".join(selectors), state="visible", timeout=timeout * 1000)
    except Exception:
        raise SignupError(f"{label} did not appear; body={_page_text(page)[:300]!r}")


def _fill(page, selectors: list[str], value: str) -> None:
    _first(page, selectors, visible=True).fill(value)


def _human_fill(page, selectors: list[str], value: str, stop=None) -> None:
    """Type a signup value progressively so GitHub's async validators run.

    `locator.fill()` injects a whole value in one DOM task. GitHub's signup
    form validates email/password/username and obtains an Octocaptcha token
    asynchronously; instant fills often leave Create account disabled. Typing
    at a modest, consistent pace plus blur matches the normal UI path.
    """
    field = _first(page, selectors, visible=True)
    _raise_if_cancelled(stop)
    # Do not pointer-click inputs here. GitHub's Octocaptcha can briefly place
    # an invisible overlay above a perfectly valid field, causing click() to
    # time out after "performing click action". DOM focus has the same input
    # semantics without needing a pointer target.
    try:
        field.focus(timeout=5_000)
    except Exception:
        field.evaluate("el => el.focus()")
    field.fill("")
    # Fixed cadence is deliberate: rapid random typing is less human than a
    # coherent typing speed. Passwords use the same path but are never logged.
    field.press_sequentially(value, delay=55)
    _raise_if_cancelled(stop)
    try:
        field.evaluate("el => el.blur()")
    except Exception:
        pass


def _form_validation_hint(page) -> str:
    """Return a concise visible validation error when Create account is disabled."""
    try:
        alerts = page.locator("[role='alert'], .is-error, .error, .flash-error").all()
        messages = []
        for alert in alerts:
            try:
                text = (alert.inner_text(timeout=500) or "").strip()
            except Exception:
                continue
            if text and "may only contain alphanumeric" not in text.lower():
                messages.append(text)
        if messages:
            return " | ".join(messages[:3])[:300]
    except Exception:
        pass
    return ""


def _click_submit(page) -> None:
    """Click the real signup Continue button, never the Google/Apple OAuth buttons.

    The signup page has 3 forms: 2 OAuth (/sessions/social/*) and 1 main
    (action contains 'signup'). Scope the submit click to the main form;
    fall back to legacy selectors for later steps (OTP/preferences pages).
    """
    scoped = page.locator("form[action*='signup'] button[type='submit']").first
    try:
        if scoped.count() and scoped.is_visible() and scoped.is_enabled():
            scoped.click()
            return
    except Exception:
        pass
    _first(page, _SUBMIT_SELECTORS, visible=True).click()


def _reject_blocked(page) -> None:
    """GitHub risk engine may force a 'Login to continue' device interstitial."""
    text = _page_text(page).lower()
    for marker in ("login to continue", "log in with a different device"):
        if marker in text:
            raise SignupBlocked(f"github risk check: {marker}")


def _cancel_order(mail, order_id: str, log) -> None:
    """Cancel the Litensi order if we bail before code is consumed.

    For Mail.cx this is a no-op (no order system).
    """
    if isinstance(mail, LitensiClient) and order_id:
        try:
            mail.set_status(order_id, "CANCELED")
            log(f"[*] litensi order {order_id} canceled")
        except Exception as exc:
            log(f"[i] litensi cancel failed (non-fatal): {exc}")


def _is_hard_block(page) -> bool:
    """DataDome hard block: 'Access is temporarily restricted' — no checkbox to solve."""
    text = ""
    try:
        text = _page_text(page).lower()
    except Exception:
        pass
    return any(marker in text for marker in _DATADOME_HARD_BLOCK_MARKERS)


def _raise_if_rate_limited(page) -> None:
    text = _page_text(page).lower()
    if any(marker in text for marker in _RATE_LIMIT_MARKERS):
        raise GitHubRateLimited(
            "GitHub secondary rate limit reached. Stop the job and wait before trying again; "
            "do not rotate/retry this limit."
        )


def _challenge_hint(page) -> str:
    """Return a short description of the anti-bot page GitHub served, or ''."""
    if "captcha-delivery" in page.url:
        return "DataDome challenge (geo.captcha-delivery.com)"
    try:
        html = page.content()[:2000]
    except Exception:
        html = ""
    if "captcha-delivery" in html or "id=\"cmsg\"" in html:
        return "DataDome challenge page"
    if "cf-chl" in html:
        return "Cloudflare challenge"
    return ""


def _try_click_datadome(page, log) -> None:
    """Best-effort click on the DataDome checkbox iframe (headed mode)."""
    try:
        for frame in page.frames:
            if "captcha-delivery" in (frame.url or ""):
                for sel in (
                    "#ddv1-test-tracking",
                    "input[type='checkbox']",
                    "[id*='checkbox']",
                    "label",
                ):
                    loc = frame.locator(sel).first
                    if loc.count() and loc.is_visible():
                        loc.click(timeout=3000)
                        log("[*] clicked DataDome checkbox")
                        return
                # no checkbox: click somewhere in the challenge frame to trigger it
                try:
                    frame.locator("body").click(timeout=3000)
                    log("[*] poked DataDome challenge frame")
                except Exception:
                    pass
                return
    except Exception:
        pass


def _form_ready(page) -> bool:
    sel = ", ".join(_EMAIL_INPUTS)
    try:
        return page.locator(sel).first.is_visible()
    except Exception:
        return False


def _open_signup(page, log, attempts: int = 3, stop=None) -> None:
    """Open github.com/signup and fight through DataDome retries/challenge.

    Strategy: direct goto first; on DataDome, try the human path
    (homepage -> click 'Sign up' link) which carries a warm session,
    then retry direct loads. Manual solve window is given at the end.
    """
    sel = ", ".join(_EMAIL_INPUTS)
    last_hint = ""
    goto_ok = True
    for attempt in range(1, attempts + 1):
        _raise_if_cancelled(stop)
        try:
            if goto_ok:
                page.goto("https://github.com/signup", wait_until="domcontentloaded", timeout=60_000)
        except Exception as exc:
            log(f"[!] goto failed ({exc}); retry {attempt}/{attempts}")
            goto_ok = False
        # wait up to 25s for the email form (JS render) or a stable challenge page
        deadline = time.time() + 25
        while time.time() < deadline:
            _raise_if_cancelled(stop)
            _raise_if_rate_limited(page)
            if _is_hard_block(page):
                raise SignupBlocked(
                    "DataDome HARD BLOCK: 'Access is temporarily restricted' — this IP is "
                    "temporarily blocked by GitHub. Change IP, disable VPN/WARP, change network, "
                    "or configure a residential proxy and retry."
                )
            if _form_ready(page):
                log("[*] github.com/signup email form is ready")
                return
            hint = _challenge_hint(page)
            if hint:
                last_hint = hint
                _try_click_datadome(page, log)
            _sleep_with_cancel(2, stop)
        if last_hint and attempt == 1:
            # human-like navigation: homepage -> Sign up link (warmer session)
            try:
                _raise_if_cancelled(stop)
                log("[*] DataDome hit — trying homepage -> 'Sign up' navigation")
                page.goto("https://github.com/", wait_until="domcontentloaded", timeout=60_000)
                if _is_hard_block(page):
                    raise SignupBlocked(
                        "DataDome HARD BLOCK: 'Access is temporarily restricted' — this IP is "
                        "temporarily blocked by GitHub. Change IP, disable VPN/WARP, change network, "
                        "or configure a residential proxy and retry."
                    )
                _sleep_with_cancel(2, stop)
                link = page.get_by_role("link", name="Sign up").first
                if link.count():
                    link.click(timeout=10_000)
                else:
                    page.goto("https://github.com/signup", wait_until="domcontentloaded", timeout=60_000)
                deadline = time.time() + 30
                while time.time() < deadline:
                    _raise_if_cancelled(stop)
                    _raise_if_rate_limited(page)
                    if _form_ready(page):
                        log("[*] email form ready via homepage navigation")
                        return
                    _try_click_datadome(page, log)
                    _sleep_with_cancel(2, stop)
            except Exception as exc:
                log(f"[!] homepage navigation failed: {exc}")
        if attempt < attempts:
            log(f"[!] {last_hint or 'form not ready'} — reload attempt {attempt + 1}/{attempts}")
    if last_hint:
        # final long wait: challenge may need a manual click in the visible window
        log(f"[!] {last_hint} — waiting up to 120s; solve the check in the browser window "
            f"if visible, or configure a residential proxy")
        _try_click_datadome(page, log)
        deadline = time.time() + 120
        while time.time() < deadline:
            _raise_if_cancelled(stop)
            _raise_if_rate_limited(page)
            if _form_ready(page):
                log("[*] challenge passed, email form is ready")
                return
            _sleep_with_cancel(2, stop)
    raise SignupError(f"email form did not appear ({last_hint or 'no challenge marker'}); "
                      f"IP is blocked by DataDome — use a residential proxy in config")


def _username_error(page) -> str:
    """Return the username validation error shown under the field, or ''.

    IMPORTANT: 'Username may only contain alphanumeric...' is a PERMANENT helper
    (id=username-helper), not an error. Real errors render inside the auto-check
    element above it (role=alert / .is-error text), e.g. 'Username is not
    available' or 'Username xyz is not available'.
    """
    try:
        # error text lives in <auto-check> successors with role=alert
        alerts = page.locator("auto-check [role='alert'], .is-error, [role='alert']").all()
        for a in alerts:
            try:
                txt = (a.inner_text(timeout=1000) or "").strip().lower()
            except Exception:
                continue
            if "username" in txt and "may only contain" not in txt:
                if "not available" in txt or "already taken" in txt:
                    return "taken"
                if txt:
                    return "invalid"
        # fallback: visible error paragraphs mentioning the typed name
        text = _page_text(page)[:1200].lower()
        if "username is not available" in text or "username is already taken" in text:
            return "taken"
    except Exception:
        pass
    return ""


def _dom_click_create_account(page) -> bool:
    """JS .click() on the ENABLED submit button — bypasses pointer hit-testing.

    When the button is enabled, JS click() runs the page's real handler (this
    is how a keyboard Enter on a focused form submits). Unlike force=True it
    does NOT fire a pointer event into whatever overlay covers the button, so
    it cannot trigger the 'Sorry, something went wrong' flash error.
    Returns True when the click landed on an enabled button.
    """
    return bool(
        page.evaluate(
            """() => {
                const form = document.querySelector("form[action*='signup']");
                const b = form && form.querySelector("button[type='submit']");
                if (!b || b.disabled) return false;
                b.click();
                return true;
            }"""
        )
    )


def _click_create_account(page, log, wait_enabled: int = 30, stop=None) -> None:
    """Click 'Create account' once it is ENABLED.

    GitHub gates the button on the octocaptcha token, so first wait for
    `disabled` to clear. Then submit in the safest order:
      1. native pointer click (most human-like)
      2. JS DOM click on the enabled button — pointer events can be eaten by
         an invisible Octocaptcha/DataDome overlay; DOM click cannot
    A force=True pointer click is deliberately NOT used: it fires a real
    pointer event at the overlay's coordinates and has produced GitHub's
    'Sorry, something went wrong' flash error.
    """
    btn = page.locator("form[action*='signup'] button[type='submit']").first
    deadline = time.time() + wait_enabled
    enabled = False
    while time.time() < deadline:
        _raise_if_cancelled(stop)
        _raise_if_rate_limited(page)
        try:
            if btn.count() and btn.is_visible() and btn.is_enabled():
                enabled = True
                break
        except Exception:
            pass
        _sleep_with_cancel(0.8, stop)
    if enabled:
        # an invisible/visible Octocaptcha overlay is often what eats the
        # pointer click — poke the captcha frame first so it can finish
        _try_click_datadome(page, log)
        try:
            btn.click(timeout=10_000)
            log("[*] 'Create account' clicked (button enabled)")
            return
        except Exception as exc:
            log(f"[i] native click intercepted ({exc}); trying DOM click on enabled button")
            if _dom_click_create_account(page):
                log("[*] 'Create account' clicked via DOM (overlay bypassed)")
                return
            log("[!] DOM click found the button disabled again — validation regressed")
    # Do not force-submit a disabled form. Its disabled state means GitHub has
    # not completed its email/password/username/Octocaptcha checks yet; forcing
    # it creates false submits, secondary rate-limit pressure, and stuck flows.
    hint = _form_validation_hint(page)
    raise SignupError(
        "Create account stayed disabled after validation wait"
        + (f": {hint}" if hint else " (Octocaptcha or async validation still pending)")
    )


def _fill_and_create_account(page, base_username: str, tries: int, log, stop=None) -> str:
    """Fill username, wait 3s, CLICK 'Create account', verify the page reacts.

    If GitHub answers with a username error, append one digit and retry
    (name -> name2 -> name3 ...). Returns the accepted username once the
    page actually moves past the signup form.
    """
    name = base_username
    for attempt in range(1, tries + 1):
        _raise_if_cancelled(stop)
        _human_fill(page, _USERNAME_INPUTS, name, stop=stop)
        # GitHub debounces username availability; wait for the server result.
        _sleep_with_cancel(3.5, stop)
        _click_create_account(page, log, stop=stop)

        # wait for reaction: error under username field OR page moving forward
        deadline = time.time() + 15
        reacted = False
        while time.time() < deadline:
            _raise_if_cancelled(stop)
            _raise_if_rate_limited(page)
            _sleep_with_cancel(1, stop)
            err = _username_error(page)
            if err == "taken":
                log(f"[*] username {name} taken, retry with +1 digit ({attempt}/{tries})")
                name = f"{base_username}{attempt + 1}"  # name2, name3, ...
                reacted = True
                break
            if err == "invalid":
                raise SignupError(f"username {name} rejected as invalid")
            # page moved on from the signup form -> submit accepted
            if not _form_ready(page):
                return name
            if "signup" not in page.url:
                return name
        if reacted:
            continue  # username was taken — loop with the next suffix
        # no error and no movement: the submit never registered (button still
        # disabled by octocaptcha?) — one JS-click retry, then fail loudly
        page.evaluate(
            """() => {
                const form = document.querySelector("form[action*='signup']");
                const b = form && form.querySelector("button[type='submit']");
                if (b) b.click();
            }"""
        )
        _sleep_with_cancel(5, stop)
        if not _form_ready(page) or "signup" not in page.url:
            return name
        raise SignupError(
            f"'Create account' did nothing after two clicks (username={name}); "
            f"octocaptcha/DataDome gate never lifted — retry the run or change IP"
        )
    raise SignupError(f"username still taken after {tries} tries (base={base_username})")


def _verify_input_visible(page) -> bool:
    """Is any e-mail verification code input visible? (launch-code page)"""
    for sel in _OTP_INPUTS:
        try:
            if page.locator(sel).first.is_visible():
                return True
        except Exception:
            continue
    return False


def _verify_page_markers(page) -> bool:
    """Text markers of the email-verification ('launch code') page."""
    try:
        text = _page_text(page)[:2000].lower()
    except Exception:
        return False
    return any(
        m in text
        for m in ("launch code", "verify your email", "check your email",
                  "enter the code", "we sent a code", "verification code")
    )


def _logged_in(context) -> bool:
    """Reliable success signal: GitHub sets cookie logged_in=yes on a real session."""
    try:
        for c in context.cookies():
            if c.get("name") == "logged_in" and str(c.get("value", "")).lower() == "yes":
                return True
    except Exception:
        pass
    return False


def _post_submit_state(page, context) -> str:
    """Classify what GitHub shows after 'Create account'.

    Returns one of:
      'verify' — email verification (launch code) page: code input visible or markers
      'done'   — logged in (cookie logged_in=yes) or a welcome/onboarding page
      'pending'— still transitioning
    """
    if _verify_input_visible(page):
        return "verify"
    if _logged_in(context):
        return "done"
    url = page.url or ""
    text = ""
    try:
        text = _page_text(page)[:2000].lower()
    except Exception:
        pass
    if _verify_page_markers(page):
        return "verify"
    if "signup" in url:
        return "pending"
    # off /signup without verify markers and without login cookie — ambiguous,
    # treat onboarding/welcome/created-successfully text as done, else pending
    if any(m in text for m in ("welcome to github", "let's get started", "get started",
                               "what do you want to do", "your github journey",
                               "your account was created successfully")):
        return "done"
    return "pending"


def _wait_post_submit(page, context, timeout: int = 120, log=None, stop=None) -> str:
    """Wait after submit until the state is stable (not 'pending').

    Anti-race: require the state to hold for 2 consecutive checks (≥4s) before
    deciding, so a mid-transition page can't be misread as 'done'.
    """
    stable_state = ""
    stable_hits = 0
    deadline = time.time() + timeout
    last_log = 0.0
    while time.time() < deadline:
        _raise_if_cancelled(stop)
        _raise_if_rate_limited(page)
        state = _post_submit_state(page, context)
        if state != "pending":
            if state == stable_state:
                stable_hits += 1
            else:
                stable_state = state
                stable_hits = 1
            if stable_hits >= 2:
                return state
        else:
            stable_state = ""
            stable_hits = 0
        if log and time.time() - last_log >= 3:
            log(f"[*] post-submit state={state or 'pending'} url={page.url}")
            last_log = time.time()
        _sleep_with_cancel(2, stop)
    raise SignupError(
        f"post-submit state never stabilized; url={page.url} "
        f"body={_page_text(page)[:200]!r}"
    )


def _browser_ctx_options(cfg: Config, log=None) -> dict:
    """Launch options tuned for DataDome (see 2026 field guides):

    - fresh_profile=True: a NEW browser per account (incognito-like, zero
      cached state — no stacked GitHub logins). The DataDome trust cookie is
      carried over separately via .datadome-trust.json (see _save_trust_cookie
      / _restore_trust_cookie) so the signup page keeps loading.
    - persistent profile (fresh_profile=False): keeps the whole profile incl.
      the `datadome` cookie (accumulated trust) — but GitHub sessions stack.
    - geoip=True: timezone/locale aligned with the (proxy) exit IP
    - os=host OS: Picasso canvas hash matches the REAL device class we run on
    - headful by default: headless rendering is a Picasso tell

    SOCKS proxies: Camoufox's own geoip probe uses plain 'socks5://' which many
    gateways (DataImpulse: '0x02 connection not allowed by ruleset') reject
    because DNS is resolved locally. For SOCKS we resolve the exit IP ourselves
    via 'socks5h://' and pass geoip=<ip> so Camoufox skips its probe.
    """
    import platform

    opts = {"headless": cfg.headless, "humanize": True, "geoip": True}
    host_os = platform.system()
    if host_os == "Darwin":
        opts["os"] = "macos"  # canvas/GPU class must match the real machine
    elif host_os == "Linux":
        opts["os"] = "linux"
    elif host_os == "Windows":
        opts["os"] = "windows"
    # sticky session FIRST: one stable exit IP for the whole job — rotating
    # IPs mid-session (DataImpulse default) are an instant DataDome flag
    proxy_url = _ensure_sticky_proxy(cfg.proxy, log=log) if (cfg.proxy or "").strip() else ""
    proxy = _parse_proxy(proxy_url) if proxy_url else None
    if proxy:
        if _proxy_needs_bridge(proxy):
            # Firefox cannot authenticate to SOCKS5 — run a local no-auth HTTP
            # bridge that relays to the authed upstream with remote DNS.
            # Reuse an already-running bridge so a NEW bridge is NOT started
            # for every fresh-profile launch (bridge is sticky-session-bound).
            global _bridge
            if _bridge is None:
                _bridge = LocalAuthProxyBridge(proxy_url)
                _bridge.start()
                if log:
                    log(f"[*] local auth bridge 127.0.0.1:{_bridge.port} -> "
                        f"{proxy['server']} (socks5 auth handled locally)")
            opts["proxy"] = _bridge.browser_proxy()
        else:
            opts["proxy"] = proxy
        if _proxy_is_socks(proxy):
            try:
                exit_ip = _socks_exit_ip(proxy_url)
                opts["geoip"] = exit_ip
                global _last_exit_ip
                _last_exit_ip = exit_ip  # consumed by trust-cookie IP binding
                if log:
                    log(f"[*] socks proxy exit IP: {exit_ip} (geoip pinned, sticky)")
            except Exception as exc:
                opts["geoip"] = False
                _last_exit_ip = None  # no IP to bind — do NOT restore stale cookies
                if log:
                    log(f"[!] socks exit-IP lookup failed ({exc}); geoip disabled — "
                        f"timezone/locale may mismatch the proxy country. "
                        f"Trust cookie will NOT be restored (IP unknown).")
    if getattr(cfg, "fresh_profile", False):
        # fresh browser per account — no user_data_dir at all
        if log:
            log("[*] fresh profile mode: browser baru tanpa cache (trust DataDome di-clone)")
    elif cfg.browser_profile_dir:
        opts["persistent_context"] = True
        opts["user_data_dir"] = str((ROOT / cfg.browser_profile_dir).resolve())
    return opts


# ---------------------------------------------------------------------------
# DataDome trust-cookie carry-over for fresh-profile mode
#
# A brand-new browser has zero cookies — DataDome will challenge it. We persist
# ONLY the `datadome` cookie (+device id) to .datadome-trust.json after each
# successful run and inject it into every fresh context. No GitHub session
# state is ever carried over, so accounts never stack.
# ---------------------------------------------------------------------------

_TRUST_FILE = ROOT / ".datadome-trust.json"
_TRUST_COOKIE_NAMES = {"datadome", "datadome_proxied", "device_id", "_device_id"}


def _save_trust_cookie(context, log=None) -> None:
    """Persist only the DataDome trust cookies, bound to the current exit IP.

    A datadome cookie issued for IP A looks forged when replayed from IP B —
    worse than no cookie at all. We therefore store the exit IP alongside and
    only restore when the IP matches (sticky session keeps it stable in-job).
    """
    try:
        cookies = context.cookies()
        keep = [
            c for c in cookies
            if c.get("name") in _TRUST_COOKIE_NAMES and c.get("domain", "").endswith("github.com")
        ]
        if not keep:
            return
        _TRUST_FILE.write_text(
            json.dumps({
                "cookies": keep,
                "exit_ip": _last_exit_ip or "",
                "saved_at": datetime.now().isoformat(timespec="seconds"),
            }),
            encoding="utf-8",
        )
        if log:
            log(f"[*] datadome trust cookie saved ({len(keep)} cookies, ip={_last_exit_ip or 'n/a'})")
    except Exception as exc:
        if log:
            log(f"[i] trust cookie save failed: {exc}")


def _restore_trust_cookie(context, log=None) -> None:
    """Inject persisted DataDome trust cookies — ONLY if the exit IP matches.

    Mismatched IP -> skip silently (a fresh challenge is less suspicious than
    a cookie replayed from the wrong IP). When exit IP is unknown (lookup
    failed), also skip — restoring a stale IP-bound cookie is worse than none.
    """
    try:
        if not _TRUST_FILE.is_file():
            return
        data = json.loads(_TRUST_FILE.read_text(encoding="utf-8"))
        cookies = data.get("cookies") or []
        if not cookies:
            return
        bound_ip = data.get("exit_ip") or ""
        # No current exit IP? Don't guess — skip restore entirely
        if not _last_exit_ip:
            if log:
                log("[i] trust cookie skipped (current exit IP is unknown; lookup failed)")
            return
        if bound_ip and _last_exit_ip and bound_ip != _last_exit_ip:
            if log:
                log(f"[i] trust cookie skipped (bound to IP {bound_ip}, current IP {_last_exit_ip})")
            return
        # context.add_cookies requires url OR domain+path
        clean = []
        for c in cookies:
            cc = {k: c.get(k) for k in ("name", "value", "domain", "path",
                                        "expires", "httpOnly", "secure", "sameSite") if c.get(k) is not None}
            if "domain" not in cc or "path" not in cc:
                cc["domain"] = ".github.com"
                cc["path"] = "/"
            clean.append(cc)
        context.add_cookies(clean)
        if log:
            log(f"[*] datadome trust cookie restored ({len(clean)} cookies, ip={bound_ip or 'unbound'})")
    except Exception as exc:
        if log:
            log(f"[i] trust cookie restore failed: {exc}")


def _context_and_page(browser):
    """Return (context, page) for BOTH launch modes.

    persistent_context=True -> Camoufox returns a BrowserContext with one page
    fresh launch             -> Camoufox returns a Browser; create a context
                                + page ourselves.
    """
    if hasattr(browser, "cookies"):  # BrowserContext (persistent mode)
        context = browser
        page = context.pages[0] if context.pages else context.new_page()
    else:  # Browser (fresh mode)
        context = browser.new_context(locale="en-US")
        page = context.new_page()
    return context, page


def _clean_github_session_cookies(context, log) -> None:
    """Between accounts: drop GitHub login cookies, keep DataDome/trust cookies.

    A persistent profile survives across accounts, so 'logged_in'/'user_session'
    cookies must be cleared to avoid signing INTO the previous account instead
    of signing UP a new one. DataDome (datadome) cookies are kept — they carry
    the anti-bot trust that lets /signup load at all.
    """
    drop = {"logged_in", "user_session", "__Host-user_session_same_site", "_gh_sess", "dotcom_user"}
    try:
        cookies = context.cookies()
        keep = [c for c in cookies if c.get("name") not in drop]
        if len(keep) == len(cookies):
            return  # nothing to clean
        context.clear_cookies()
        for c in keep:
            try:
                context.add_cookies([c])
            except Exception:
                pass
        log("[*] session cookies cleared (DataDome trust kept)")
    except Exception as exc:
        log(f"[i] cookie cleanup skipped: {exc}")


def _fill_launch_code(page, code: str, log) -> None:
    """Fill the 8-box launch-code page (one digit per #launch-code-N input).

    Falls back to a single OTP input when the boxes are not present.
    """
    boxes = page.locator("input[id^='launch-code-']")
    count = boxes.count()
    if count >= len(code):  # 8 boxes for an 8-digit code
        for i, digit in enumerate(code):
            boxes.nth(i).fill(digit)
            time.sleep(0.15)  # small human cadence between boxes
        log(f"[*] launch code typed into {len(code)} boxes")
        try:
            page.locator(
                "button[class*='Button--primary'], button[class*='Button-module__Button--primary']"
            ).first.click(timeout=5000)
            log("[*] launch code submitted")
        except Exception:
            log("[*] no submit button found — launch code may auto-submit")
        return
    # single input fallback
    otp = _first(page, _OTP_INPUTS, visible=True)
    if not otp.input_value():
        otp.fill(code)
    _click_submit(page)
    log("[*] OTP submitted")


_LOGIN_INPUTS = ["#login_field", "input[name='login']", "input#login"]
_LOGIN_PASS_INPUTS = ["#password", "input[name='password']", "input[type='password']"]


def _try_login(page, username: str, password: str, context, log) -> bool:
    """GitHub sends fresh signups to /login: sign in to obtain logged_in=yes.

    Returns True when the login cookie is present afterwards.
    """
    try:
        user = page.locator(", ".join(_LOGIN_INPUTS)).first
        if not user.is_visible():
            return _logged_in(context)
        user.fill(username, timeout=5000)
        page.locator(", ".join(_LOGIN_PASS_INPUTS)).first.fill(password, timeout=5000)
        time.sleep(0.5)
        # the sign-in button lives in form[action='/session'] but is NOT
        # type=submit (only Google/Apple are). Click the form's own button.
        page.evaluate(
            """() => {
                const form = document.querySelector("form[action*='session']");
                if (!form) return;
                // prefer a real submit element, else the last button in the form
                let btn = form.querySelector("input[type='submit'], button:not([type='button'])");
                if (!btn) {
                    const btns = form.querySelectorAll("button");
                    btn = btns[btns.length - 1];
                }
                if (btn) btn.click();
            }"""
        )
        log("[*] login form submitted after signup")
    except Exception as exc:
        log(f"[i] auto-login skipped: {exc}")
    deadline = time.time() + 30
    while time.time() < deadline:
        if _logged_in(context):
            return True
        time.sleep(1.5)
    return False


def _create_repository(page, username: str, base_name: str, log) -> str:
    """Stage 4 (user recording): create the first repository on /new.

    The name field auto-generates a suggestion; we type our own name and submit.
    Returns the repository name created.
    """
    def _submit() -> None:
        """Submit the visible enabled repo form without clicking an overlay."""
        btn = page.get_by_role("button", name="Create repository").first
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                if btn.count() and btn.is_visible() and btn.is_enabled():
                    break
            except Exception:
                pass
            time.sleep(0.5)
        else:
            raise SignupError("Create repository stayed disabled after validation wait")

        try:
            btn.click(timeout=10_000)
            log("[*] 'Create repository' clicked")
            return
        except Exception as exc:
            log(f"[i] repository native click intercepted ({exc}); trying DOM click")

        clicked = bool(page.evaluate(
            """() => {
                const buttons = [...document.querySelectorAll('button')];
                const button = buttons.find((b) =>
                    b.offsetParent !== null && !b.disabled &&
                    (b.textContent || '').trim() === 'Create repository'
                );
                if (!button) return false;
                button.click();
                return true;
            }"""
        ))
        if not clicked:
            raise SignupError("Create repository button was not visible/enabled for DOM click")
        log("[*] 'Create repository' clicked via DOM (overlay bypassed)")

    name = base_name or "hello"
    page.goto("https://github.com/new", wait_until="domcontentloaded", timeout=60_000)
    try:
        page.wait_for_selector("#repository-name-input", state="visible", timeout=30_000)
    except Exception:
        raise SignupError(f"repo form not found; url={page.url} body={_page_text(page)[:200]!r}")
    inp = page.locator("#repository-name-input").first
    inp.fill(name)
    time.sleep(1.5)  # let GitHub validate + enable the submit button
    try:
        _submit()
    except Exception as exc:
        raise SignupError(f"cannot click 'Create repository': {exc}")
    # success = redirected to /<username>/<repo>
    deadline = time.time() + 30
    while time.time() < deadline:
        url = page.url or ""
        if "/new" not in url and f"/{username}/" in url:
            log(f"[*] repository created: {url}")
            return name
        # name conflict? GitHub shows an error — retry with a numeric suffix
        err = ""
        try:
            err = _page_text(page)[:600].lower()
        except Exception:
            pass
        if "already exists" in err and "/new" in url:
            log(f"[*] repo {name} exists, retry with suffix")
            name = f"{base_name}{int(time.time()) % 10000}"
            page.goto("https://github.com/new", wait_until="domcontentloaded", timeout=60_000)
            page.wait_for_selector("#repository-name-input", state="visible", timeout=20_000)
            page.locator("#repository-name-input").first.fill(name)
            time.sleep(1.5)
            _submit()
        time.sleep(1)
    raise SignupError(f"repository creation not confirmed; url={page.url}")


def _fetch_public_profile() -> dict[str, str]:
    """Fetch one display identity and one quote without using their credentials."""
    random_user = requests.get("https://randomuser.me/api/", timeout=15).json()
    quote = requests.get("https://zenquotes.io/api/random", timeout=15).json()
    return parse_public_profile(random_user, quote)


def _visible_dom_click(page, matcher_js: str) -> bool:
    """Click a visible enabled button through DOM when overlays eat pointer input."""
    return bool(page.evaluate(
        f"""() => {{
            const button = [...document.querySelectorAll('button')].find({matcher_js});
            if (!button || button.disabled || button.offsetParent === null) return false;
            button.click();
            return true;
        }}"""
    ))


def _complete_profile(page, username: str, cfg: Config, log) -> None:
    """Set recorded status and public profile fields after 2FA is secured."""
    if not (cfg.set_profile_status or cfg.complete_profile):
        return
    profile = None
    if cfg.complete_profile:
        custom = {
            "name": cfg.profile_name.strip(),
            "bio": cfg.profile_bio.strip(),
            "location": cfg.profile_location.strip(),
        }
        # Avoid external APIs entirely when every profile field is configured.
        profile = _fetch_public_profile() if not all(custom.values()) else {}
        profile = {key: custom[key] or profile[key] for key in custom}
    page.goto(f"https://github.com/{username}", wait_until="domcontentloaded", timeout=60_000)

    if cfg.set_profile_status:
        status = cfg.profile_status.strip() or "On vacation"
        # Recording: profile -> react-partial-anchor button "Set status" ->
        # #user-status-status-input -> portal "Set status" submit button.
        # Do not use the preset chip: it is not present on a fresh profile.
        launcher = page.locator("react-partial-anchor button, button").filter(
            has_text="Set status"
        ).first
        launcher_opened = False
        try:
            launcher.click(timeout=8_000)
            launcher_opened = True
        except Exception:
            launcher_opened = _visible_dom_click(
                page,
                "b => /status/i.test(b.getAttribute('aria-label') || '') || "
                "(b.textContent || '').trim() === 'Set status'",
            )
            if not launcher_opened:
                log("[i] profile status launcher not found; status skipped")
            else:
                log("[*] profile status launcher clicked via DOM")
        if launcher_opened:
            status_input = page.locator("#user-status-status-input").first
            try:
                status_input.wait_for(state="visible", timeout=8_000)
            except Exception:
                raise SignupError("profile status popup did not open")
            status_input.fill(status, timeout=8_000)
            if status_input.input_value(timeout=3_000) != status:
                raise SignupError("profile status input did not retain the configured value")

            submit = page.locator("#__primerPortalRoot__ button").filter(
                has_text="Set status"
            ).last
            try:
                submit.click(timeout=8_000)
            except Exception:
                if not _visible_dom_click(
                    page,
                    "b => b.closest('#__primerPortalRoot') && "
                    "(b.textContent || '').trim() === 'Set status'",
                ):
                    raise SignupError("cannot submit profile status")
                log(f"[*] profile status submitted via DOM: {status}")

            # A successful submit closes the status popup. It is the reliable
            # confirmation independent of profile-page text rendering timing.
            deadline = time.time() + 10
            while time.time() < deadline:
                try:
                    if not status_input.is_visible():
                        log(f"[*] profile status saved: {status}")
                        break
                except Exception:
                    log(f"[*] profile status saved: {status}")
                    break
                time.sleep(0.4)
            else:
                raise SignupError(f"profile status did not save: {status}")

    if not profile:
        return
    edit_button = page.locator("button[name='button']").filter(has_text="Edit profile").first
    try:
        edit_button.click(timeout=10_000)
    except Exception as exc:
        log(f"[i] Edit profile native click intercepted ({exc}); trying DOM click")
        if not _visible_dom_click(
            page,
            "b => (b.textContent || '').trim() === 'Edit profile' || "
            "b.classList.contains('js-profile-editable-edit-button')",
        ):
            raise SignupError("cannot open Edit profile (button not found for DOM click)")
        log("[*] Edit profile clicked via DOM (overlay bypassed)")

    name_input = page.locator("#user_profile_name").first
    bio_input = page.locator("#user_profile_bio").first
    location_input = page.locator("input[name='user[profile_location]']").first
    for field in (name_input, bio_input, location_input):
        field.wait_for(state="visible", timeout=15_000)
    name_input.fill(profile["name"])
    bio_input.fill(profile["bio"])
    location_input.fill(profile["location"])

    try:
        page.locator(f"form[action='/users/{username}'] button").filter(
            has_text="Save"
        ).first.click(timeout=10_000)
    except Exception:
        if not _visible_dom_click(page, "b => (b.textContent || '').trim() === 'Save'"):
            raise SignupError("cannot submit Edit profile")
    try:
        page.wait_for_timeout(1_500)
        # After a successful save, either profile text is rendered or the form
        # retains the saved input value during its partial refresh.
        if profile["name"] not in _page_text(page) and name_input.input_value() != profile["name"]:
            raise SignupError("profile save was not confirmed")
    except SignupError:
        raise
    except Exception:
        pass
    log(f"[*] profile completed: {profile['name']} | {profile['location']}")


def _enable_2fa(page, log) -> tuple[str, str]:
    """Stage 5 (user recording): enable TOTP 2FA and return the secret.

    Flow (from the recording):
      Settings → Password and authentication → 'Enable two-factor authentication'
      → 'Authenticator apps and browser extension' → click 'setup key' to reveal
      the secret in a textfield → READ the secret → compute TOTP via pyotp →
      fill input[name='otp'] → Continue → save recovery codes → 'I have saved my
      recovery codes' → Done.
    """
    import pyotp

    page.goto("https://github.com/settings/security", wait_until="domcontentloaded", timeout=60_000)
    try:
        page.wait_for_selector("#settings-frame", state="visible", timeout=30_000)
    except Exception:
        raise SignupError(f"security settings page failed; url={page.url}")

    # 'Enable two-factor authentication' is an <a href> link (NOT a button):
    # /settings/two_factor_authentication/setup/intro — navigate straight to it.
    # NOTE: GitHub REGENERATES the TOTP secret on every load of this page, so
    # read the secret only from the page we actually fill the code into.
    try:
        with page.expect_navigation(wait_until="domcontentloaded", timeout=30_000):
            page.goto(
                "https://github.com/settings/two_factor_authentication/setup/intro",
                wait_until="domcontentloaded", timeout=60_000,
            )
    except Exception:
        pass  # already on the page; proceed

    # wait for the setup wizard (QR code page shows the secret in a hidden dialog)
    try:
        page.wait_for_selector(
            "div[data-target='two-factor-setup-verification.mashedSecret']",
            state="attached",  # present in DOM even while the dialog is closed
            timeout=45_000,
        )
    except Exception:
        raise SignupError(f"2FA setup wizard did not load; url={page.url}")

    # reveal the setup key via the 'setup key' button (mirrors the recording),
    # then read the secret from the dialog's data-target div.
    try:
        page.locator("#dialog-show-two-factor-setup-verification-mashed-secret").first.click(
            timeout=10_000
        )
        time.sleep(0.8)
    except Exception:
        pass  # dialog content is in the DOM even when closed — read anyway

    secret = ""
    try:
        secret = (
            page.locator(
                "div[data-target='two-factor-setup-verification.mashedSecret']"
            ).first.inner_text(timeout=5000)
            or ""
        ).strip()
    except Exception:
        pass
    if not secret:
        # fallback: scan page HTML for a base32-looking secret (16-32 chars)
        import re

        body = ""
        try:
            body = page.content()
        except Exception:
            body = ""
        m = re.search(r"\b([A-Z2-7]{16,32})\b", body or "")
        if m:
            secret = m.group(1)
    if not secret or len(secret) < 16:
        raise SignupError(f"TOTP secret not found (got {secret!r})")
    log(f"[*] TOTP secret captured: {secret}")

    # close the setup-key dialog if it opened
    try:
        page.locator("[aria-label='Close']").first.click(timeout=3000)
    except Exception:
        pass

    # compute the current TOTP code and submit it
    totp = pyotp.TOTP(secret)
    code = totp.now()
    log(f"[*] TOTP code generated: {code}")
    # the ENABLED otp input is the one with aria-label; input[name='otp'] is a
    # hidden/disabled twin (from the recording) — fill the enabled one.
    otp_input = page.locator(
        "input[aria-label='Verify the code from the app']:not([disabled])"
    ).first
    try:
        otp_input.fill(code, timeout=10_000)
    except Exception:
        otp_input = page.locator("input[name='otp']:not([disabled])").first
        otp_input.fill(code, timeout=10_000)

    # --- helper: click the VISIBLE enabled wizard button by its label ---
    # The wizard keeps all steps' buttons in the DOM; Playwright's is_visible()
    # is unreliable there, so use the browser's own visibility semantics
    # (offsetParent !== null) to find the ACTIVE step's button.
    def _click_active_wizard_button(page, label: str) -> bool:
        try:
            clicked = page.evaluate(
                """(label) => {
                    const btns = [...document.querySelectorAll(
                        "button[data-target='single-page-wizard-step.nextButton'], " +
                        "button[data-action='click:two-factor-setup-recovery-codes#onDownloadClick'], " +
                        "button[data-action='click:single-page-wizard-step#onNext']"
                    )];
                    for (const b of btns) {
                        if (b.offsetParent !== null && !b.disabled &&
                            (b.textContent || '').trim().toLowerCase() === label.toLowerCase()) {
                            b.click();
                            return true;
                        }
                    }
                    return false;
                }""",
                label,
            )
            return bool(clicked)
        except Exception:
            return False

    if not _click_active_wizard_button(page, "Continue"):
        # fallback: any visible enabled next button (its label may be icon-only)
        try:
            page.evaluate(
                """() => {
                    const btns = [...document.querySelectorAll(
                        "button[data-target='single-page-wizard-step.nextButton']"
                    )];
                    for (const b of btns) {
                        if (b.offsetParent !== null && !b.disabled) { b.click(); return true; }
                    }
                    return false;
                }"""
            )
        except Exception:
            pass
    log("[*] TOTP code submitted → Continue")
    time.sleep(3)

    # ---- recovery codes step ----
    recovery = ""
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            # prefer the dedicated element, else scan the page text
            codes: list[str] = []
            try:
                rc_el = page.locator("two-factor-setup-recovery-codes, [data-target='two-factor-setup-recovery-codes']")
                if rc_el.count():
                    txt = rc_el.first.inner_text(timeout=3000) or ""
                else:
                    txt = _page_text(page)
            except Exception:
                txt = _page_text(page)
            import re as _re

            codes = list(dict.fromkeys(_re.findall(r"\b[a-z0-9]{5,6}-[a-z0-9]{5,6}\b", txt, _re.I)))
            if codes:
                recovery = "\n".join(codes[:16])
                break
            time.sleep(1)
        if recovery:
            log(f"[*] recovery codes captured ({len(recovery.splitlines())} codes)")
    except Exception:
        pass

    # download recovery codes (as recorded), then confirm & finish
    try:
        with page.expect_download(timeout=10_000) as dl_info:
            page.evaluate(
                """() => {
                    const b = [...document.querySelectorAll('button')].find(
                        b => b.offsetParent !== null && !b.disabled &&
                             /download/i.test((b.textContent || '').trim())
                    );
                    if (b) b.click();
                }"""
            )
        download = dl_info.value
        log(f"[*] recovery codes downloaded: {download.suggested_filename}")
        try:
            path = str(download.path())
            if path and os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    dl_text = f.read()
                if dl_text and not recovery:
                    import re as _re

                    codes = list(dict.fromkeys(_re.findall(r"\b[a-z0-9]{5,6}-[a-z0-9]{5,6}\b", dl_text, _re.I)))
                    if codes:
                        recovery = "\n".join(codes[:16])
                        log(f"[*] recovery codes from download ({len(codes)} codes)")
        except Exception:
            pass
    except Exception as exc:
        log(f"[i] recovery codes download skipped: {exc}")

    if _click_active_wizard_button(page, "I have saved my recovery codes"):
        log("[*] recovery codes confirmed")
    else:
        # fallback: click by data-action nextButton (visible one)
        page.evaluate(
            """() => {
                const btns = [...document.querySelectorAll(
                    "button[data-target='single-page-wizard-step.nextButton']"
                )];
                for (const b of btns) {
                    if (b.offsetParent !== null && !b.disabled) { b.click(); return true; }
                }
                return false;
            }"""
        )
        log("[*] recovery codes confirmed (fallback)")
    time.sleep(2)
    if _click_active_wizard_button(page, "Done"):
        log("[*] 2FA wizard finished")
    else:
        page.evaluate(
            """() => {
                const btns = [...document.querySelectorAll(
                    "button[data-target='single-page-wizard-step.nextButton']"
                )];
                for (const b of btns) {
                    if (b.offsetParent !== null && !b.disabled) { b.click(); return true; }
                }
                return false;
            }"""
        )
    time.sleep(2)

    # persist recovery codes next to the accounts file for account recovery
    if recovery:
        try:
            rc_path = ROOT / "github_recovery_codes.txt"
            with rc_path.open("a", encoding="utf-8") as f:
                f.write(f"=== {page.url} @ {datetime.now().isoformat(timespec='seconds')} ===\n")
                f.write(recovery + "\n\n")
            log(f"[*] recovery codes saved to {rc_path.name}")
        except Exception as exc:
            log(f"[i] recovery codes write failed: {exc}")
    return secret, recovery


def _fill_signup_form(page, cfg, email, password, log, stop) -> str:
    """Fill the single-page signup form (email -> password -> username).

    Returns the accepted username. Raises SignupError with a clear reason when
    the form cannot be completed (validation error, overlay, rate limit).
    """
    # Fill in the same order as a person: email -> wait -> password ->
    # wait -> username. Each blur gives GitHub's async form validators and
    # Octocaptcha time to settle before Create account is considered.
    _human_fill(page, _EMAIL_INPUTS, email, stop=stop)
    _sleep_with_cancel(1.5, stop)
    _raise_if_rate_limited(page)
    _human_fill(page, _PASSWORD_INPUTS, password, stop=stop)
    _sleep_with_cancel(1.5, stop)
    _raise_if_rate_limited(page)
    # 3s pause after username -> CLICK Create account -> on username error
    # append one digit and retry (name -> name2 -> name3 ...)
    return _fill_and_create_account(
        page, username_from_email(email), cfg.max_username_tries, log, stop=stop
    )


def _post_form_flow(
    page, context, cfg: Config, email: str, password: str, username: str,
    mail, order_id: str, log, stop,
) -> tuple[str, str, str]:
    """Everything AFTER the signup form was accepted: email verification
    (launch code), auto-login, first repository (stage 4), TOTP 2FA (stage 5).
    Returns (username, totp_secret, recovery_codes)."""
    # after submit GitHub either shows the email verification (launch code)
    # page, or (high-trust sessions) logs straight in.
    state = _wait_post_submit(page, context, timeout=120, log=log, stop=stop)
    if state == "verify":
        log(f"[*] verification page: {page.url}")
        code = mail.wait_for_code(
            order_id,
            timeout=cfg.otp_timeout_sec,
            log=log,
            cancel_cb=stop,
            email=email,
        )
        log(f"[*] verification code: {code}")
        _fill_launch_code(page, code, log)
        # mail.cx has no order confirmation — code already extracted
        log(f"[*] verification code extracted and submitted")
        # after OTP: must reach a logged-in state
        state2 = _wait_post_submit(page, context, timeout=90, log=log, stop=stop)
        if state2 == "verify":
            raise SignupError("verification code rejected (still on verify page)")
    # state 'done' required — no more accepting bare redirects
    totp_secret = ""
    recovery = ""
    deadline = time.time() + 60
    while time.time() < deadline:
        _raise_if_cancelled(stop)
        _raise_if_rate_limited(page)
        if _logged_in(context):
            log("[*] logged_in cookie confirmed — account is active")
            # ---- stage 4: create first repository ----
            if cfg.create_repo:
                try:
                    _create_repository(page, username, cfg.repo_name, log)
                except Exception as exc:
                    log(f"[i] create repo stage skipped: {exc}")
            # ---- stage 5: enable TOTP 2FA ----
            if cfg.enable_2fa:
                try:
                    totp_secret, recovery = _enable_2fa(page, log)
                except Exception as exc:
                    log(f"[i] 2FA stage failed (account still saved): {exc}")
            _save_recovery_per_account(email, recovery, log)
            try:
                _complete_profile(page, username, cfg, log)
            except Exception as exc:
                log(f"[i] profile stage skipped (account still saved): {exc}")
            _save_trust_cookie(context, log)  # persist DataDome trust for the next fresh run
            return username, totp_secret, recovery
        # GitHub sends fresh signups to /login: sign in with the new creds
        if "/login" in (page.url or ""):
            if _try_login(page, email, password, context, log):
                log("[*] logged_in cookie confirmed after auto-login")
                # ---- stage 4: create first repository ----
                if cfg.create_repo:
                    try:
                        _create_repository(page, username, cfg.repo_name, log)
                    except Exception as exc:
                        log(f"[i] create repo stage skipped: {exc}")
                # ---- stage 5: enable TOTP 2FA ----
                if cfg.enable_2fa:
                    try:
                        totp_secret, recovery = _enable_2fa(page, log)
                    except Exception as exc:
                        log(f"[i] 2FA stage failed (account still saved): {exc}")
                _save_recovery_per_account(email, recovery, log)
                try:
                    _complete_profile(page, username, cfg, log)
                except Exception as exc:
                    log(f"[i] profile stage skipped (account still saved): {exc}")
                _save_trust_cookie(context, log)  # persist DataDome trust for the next fresh run
                return username, totp_secret, recovery
            raise SignupError("auto-login after signup failed")
        if _post_submit_state(page, context) == "pending":
            _sleep_with_cancel(2, stop)
            continue
        if _wait_post_submit(page, context, timeout=20, log=log, stop=stop) == "done":
            continue  # loop will hit the _logged_in check above
        _sleep_with_cancel(2, stop)
    raise SignupError(
        f"account not confirmed logged-in after flow; url={page.url} "
        f"body={_page_text(page)[:200]!r}"
    )


def _run_signup(
    cfg: Config,
    email: str,
    password: str,
    mail: MailCxClient,
    order_id: str,
    log,
    stop,
) -> tuple[str, str]:
    """Run the whole sign-up; returns (username, totp).

    GitHub's signup is now a SINGLE page: Email* / Password* / Username* in one
    form (action=/signup?social=false), submit = "Create account" button.
    OAuth (Google/Apple) buttons live in separate <form> tags — never click them.

    The Octocaptcha token sometimes never settles on a given page load — the
    Create account button stays disabled forever. Two-tier retry strategy:

    Tier 1 (fast, cheap): within the SAME browser session, do `page.reload()`
    (Cmd+R equivalent) and re-fill the form with the SAME data (email +
    password + username). Up to `page_reloads` in-session retries.

    Tier 2 (slow, expensive): if Tier 1 exhausts, close the browser and open
    a completely fresh session (new fingerprint / cookies) and try again. Up
    to `session_reloads` full-session restarts.
    """
    page_reloads = 3      # in-session refresh (Cmd+R) attempts before switching session
    session_reloads = 2   # full browser restarts (new fingerprint) after page reloads fail
    last_exc: Exception | None = None
    for session_attempt in range(1, session_reloads + 2):
        _raise_if_cancelled(stop)
        if session_attempt > 1:
            log(f"[*] SESSION switch {session_attempt - 1}/{session_reloads} "
                f"(fresh browser + new fingerprint)")
        with Camoufox(**_browser_ctx_options(cfg, log=log if session_attempt == 1 else None)) as browser:
            # works for BOTH modes: persistent context (BrowserContext) and fresh
            # launch (Browser -> new context/page per account)
            context, page = _context_and_page(browser)
            if getattr(cfg, "fresh_profile", False):
                # fresh mode: inject ONLY the DataDome trust cookie (no GitHub state)
                _restore_trust_cookie(context, log)
            else:
                # persistent mode: wipe login state, keep DataDome trust cookies
                _clean_github_session_cookies(context, log)
            page.set_default_timeout(20_000)
            _open_signup(page, log, stop=stop, attempts=2 if session_attempt > 1 else 3)
            _reject_blocked(page)

            # --- Tier 1: in-session page reloads with same data ---
            page_last_exc: Exception | None = None
            username: str | None = None
            for page_attempt in range(1, page_reloads + 1):
                _raise_if_cancelled(stop)
                if page_attempt > 1:
                    log(f"[*] PAGE reload {page_attempt - 1}/{page_reloads - 1} "
                        f"(Reload with same data)")
                    try:
                        page.reload(wait_until="domcontentloaded", timeout=60_000)
                    except Exception as exc:
                        log(f"[!] page.reload() failed ({exc}); falling back to goto()")
                        try:
                            page.goto(
                                "https://github.com/signup",
                                wait_until="domcontentloaded",
                                timeout=60_000,
                            )
                        except Exception as exc2:
                            page_last_exc = SignupError(f"page reload/goto failed: {exc2}")
                            break
                    # wait for the form to be ready again on the reloaded page
                    deadline = time.time() + 30
                    while time.time() < deadline:
                        _raise_if_cancelled(stop)
                        _raise_if_rate_limited(page)
                        if _form_ready(page):
                            break
                        _sleep_with_cancel(1, stop)
                    else:
                        page_last_exc = SignupError("form not ready after page reload")
                        continue
                    _reject_blocked(page)

                try:
                    username = _fill_signup_form(page, cfg, email, password, log, stop)
                    log(f"[*] form submitted: email + password + username={username}")
                    break  # success — leave Tier 1 loop
                except SignupError as exc:
                    msg = str(exc)
                    reloadable = (
                        "stayed disabled" in msg
                        or "click" in msg.lower()
                        or "overlay" in msg.lower()
                        or "form" in msg.lower()
                    )
                    if reloadable and page_attempt < page_reloads:
                        page_last_exc = exc
                        log(f"[!] page attempt {page_attempt}/{page_reloads} failed "
                            f"({msg[:120]}); will refresh page and retry with same data")
                        continue
                    # either not-reloadable, or Tier 1 exhausted -> propagate to Tier 2 handler
                    page_last_exc = exc
                    break

            if username is None:
                # Tier 1 failed — decide whether to switch session (Tier 2)
                exc = page_last_exc or SignupError("form submit failed with unknown reason")
                msg = str(exc)
                reloadable = (
                    "stayed disabled" in msg
                    or "click" in msg.lower()
                    or "overlay" in msg.lower()
                    or "form" in msg.lower()
                )
                if reloadable and session_attempt <= session_reloads:
                    last_exc = exc
                    log(f"[!] {page_reloads} page-reloads exhausted; switching SESSION "
                        f"({msg[:120]})")
                    continue  # browser closes here; outer loop starts a fresh one
                raise exc

            # form accepted — continue with the rest of the flow in this same session
            return _post_form_flow(
                page, context, cfg, email, password, username,
                mail, order_id, log, stop,
            )
            # non-SignupError exceptions propagate immediately (with-block closes browser)
    raise SignupError(
        f"signup form never completed after {page_reloads} page-reloads x "
        f"{session_reloads + 1} sessions: {last_exc}"
    )


def register_one(
    cfg: Config, log: Callable[[str], None], cancel_cb: Optional[Callable[[], bool]] = None
) -> Optional[str]:
    """Register one account; returns its one-line account record or None."""
    stop = cancel_cb or (lambda: False)

    # --- create mail client based on provider ---
    provider = getattr(cfg, "mail_provider", "mailcx") or "mailcx"
    if provider == "litensi":
        mail = LitensiClient(
            api_id=cfg.litensi_api_id,
            api_key=cfg.litensi_api_key,
            site=cfg.litensi_site,
            zone=cfg.litensi_zone,
        )
    else:
        mail = MailCxClient(domain=cfg.mailcx_domain)
    email, order_id = mail.create_mailbox()
    log(f"[*] mailbox: {email} ({provider})")

    try:
        password = generate_password()
        hard_left = int(getattr(cfg, "proxy_hard_block_retries", 0) or 0) if cfg.proxy else 0
        rate_left = int(getattr(cfg, "proxy_rate_limit_retries", 0) or 0) if cfg.proxy else 0
        while True:
            _raise_if_cancelled(stop)
            try:
                username, totp_secret, recovery = _run_signup(
                    cfg, email, password, mail, order_id, log, stop
                )
                break
            except SignupBlocked as exc:
                if hard_left <= 0:
                    raise
                hard_left -= 1
                log(f"[!] DataDome hard block ({exc}); disabling proxy + rotating, {hard_left} retries left")
                _disable_blocked_proxy(log)
                _rotate_sticky_proxy()
                _sleep_with_cancel(5, stop)
            except GitHubRateLimited as exc:
                if rate_left <= 0:
                    raise
                rate_left -= 1
                log(f"[!] GitHub secondary rate limit ({exc}); rotating sticky proxy/IP, "
                    f"{rate_left} retries left")
                _rotate_sticky_proxy()
                _sleep_with_cancel(8, stop)
        # Recovery codes are stored in accounts/recovery/<email-hash>.txt.
        # This fifth marker lets the account UI show the recovery-code action
        # without exposing the codes in the main account list.
        return f"{email}----{password}----{username}----{totp_secret}----{int(bool(recovery))}"
    except KeyboardInterrupt:
        raise
    except RegistrationCancelled:
        raise
    except GitHubRateLimited:
        raise
    except Exception as exc:
        log(f"[-] account failed: {exc}")
        return None
    finally:
        if provider == "litensi":
            # confirm or cancel the Litensi order depending on outcome
            _cancel_order(mail, order_id, log)
        else:
            log("[*] mailbox cleanup: no action needed (mail.cx)")


def run_job(
    cfg: Config,
    cancel_cb: Optional[Callable[[], bool]] = None,
    log: Optional[Callable[[str], None]] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> tuple[int, int, Path]:
    """Register `register_count` accounts; returns (ok, fail, output_file).

    `progress_cb(ok, fail)` (optional) is invoked after each account attempt so
    external observers (e.g. the web UI) can render live stats instead of only
    seeing the final totals when the job returns.
    """
    if log is None:
        log = lambda msg: print(f"[{_now()}] {msg}")  # noqa: E731
    stop = cancel_cb or (lambda: False)

    def _emit_progress(ok_count: int, fail_count: int) -> None:
        if progress_cb is None:
            return
        try:
            progress_cb(ok_count, fail_count)
        except Exception as exc:
            # progress reporting must never break the job
            log(f"[i] progress_cb error ignored: {exc}")

    ACCOUNTS_DIR.mkdir(parents=True, exist_ok=True)
    out = ACCOUNTS_DIR / f"github_accounts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    ok = fail = 0
    log(f"[*] github-regkit | engine=Camoufox (Firefox anti-detect) | mail_provider=mail.cx "
        f"| headless={cfg.headless} | target={cfg.register_count} | output={out.name}")
    _emit_progress(ok, fail)  # initial snapshot: 0/0
    try:
        for i in range(1, cfg.register_count + 1):
            if stop():
                break
            log(f"--- account {i}/{cfg.register_count} ---")
            line = None
            try:
                line = register_one(cfg, log, stop)
            except KeyboardInterrupt:
                raise
            except RegistrationCancelled:
                log("[!] stop requested — browser flow cancelled")
                break
            except GitHubRateLimited as exc:
                log(f"[!] rate-limit retries exhausted — stopping job: {exc}")
                break
            except (MailCxError, LitensiError) as exc:  # provider-level error: abort job
                log(f"[!] mail provider error, aborting: {exc}")
                break
            if line:
                with out.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
                ok += 1
                log(f"[+] {line.split('----')[0]} saved to {out.name}")
            else:
                fail += 1
            log(f"[*] stats: OK {ok} | FAIL {fail}")
            _emit_progress(ok, fail)  # live update after each account
            if i < cfg.register_count and not stop():
                _sleep_with_cancel(cfg.delay_sec, stop)
    except RegistrationCancelled:
        # A web Stop click may arrive during inter-account delay, not only
        # inside register_one. This is expected control flow, not a job error.
        log("[!] stop requested — job ended cleanly")
    finally:
        _stop_proxy_bridge()  # stop the local auth bridge if it was started
        log(f"[*] done: OK {ok} | FAIL {fail}")
        _emit_progress(ok, fail)  # final snapshot
    return ok, fail, out
