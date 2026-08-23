"""Mail.cx temporary email API client.

Mail.cx is a free disposable email service — no inbox creation needed.
The mailbox is implicit: mail starts buffering the moment SMTP accepts it.

System domains (from GET /v1/config): uqu.me (default), ddker.com, 9k3r.com

Endpoints used:
  GET  /v1/config                 → available domains (cached)
  GET  /v1/inbox/<address>        → long-poll emails (25s timeout, 204=nothing)
"""
from __future__ import annotations

import random
import re
import string
import time
from typing import Callable, Optional

import requests

API_BASE = "https://mail.cx/v1"

# Default system domains — fetched live from /v1/config on first use
_DEFAULT_DOMAINS = ["uqu.me", "ddker.com", "9k3r.com"]

# Localpart rules (from /v1/config):
#   2-20 chars, lowercase alphanumeric + . _ -
_LOCALPART_CHARS = string.ascii_lowercase + string.digits + "._-"
_LOCALPART_MIN = 4
_LOCALPART_MAX = 16

# Reserved localparts that mail.cx rejects
_RESERVED = {
    "abuse", "admin", "administrator", "billing", "compliance", "contact",
    "daemon", "do-not-reply", "donotreply", "finance", "ftp", "help",
    "helpdesk", "hostmaster", "info", "legal", "mail", "mailer",
    "mailer-daemon", "marketing", "no-reply", "nobody", "noreply",
    "payment", "postmaster", "privacy", "root", "sales", "secadmin",
    "security", "service", "ssl-admin", "support", "system", "webmaster",
    "www",
}


class MailCxError(RuntimeError):
    pass


class MailCxClient:
    """Mail.cx temp email client — no authentication needed for free tier.

    The mailbox is implicit: generate any localpart@domain and start polling.
    """

    def __init__(self, domain: str = ""):
        self.domain = domain
        self.session = requests.Session()
        self._domains: list[str] = []
        self._last_email: str = ""

    def _get_domains(self) -> list[str]:
        """Fetch available domains from /v1/config (cached)."""
        if self._domains:
            return self._domains
        try:
            resp = self.session.get(
                f"{API_BASE}/config",
                headers={"Accept": "application/json"},
                timeout=10,
            )
            data = resp.json()
            domains = data.get("system_domains", [])
            self._domains = [d["domain"] for d in domains if isinstance(d, dict)]
        except Exception:
            self._domains = list(_DEFAULT_DOMAINS)
        return self._domains or _DEFAULT_DOMAINS

    def _pick_domain(self) -> str:
        """Pick a domain: user-configured or random from available."""
        if self.domain:
            return self.domain
        domains = self._get_domains()
        return random.choice(domains)

    @staticmethod
    def _random_localpart() -> str:
        """Generate a random localpart: 4-16 chars, alphanumeric."""
        length = random.randint(_LOCALPART_MIN, _LOCALPART_MAX)
        chars = string.ascii_lowercase + string.digits
        part = "".join(random.choices(chars, k=length))
        # Avoid reserved words
        if part in _RESERVED:
            part = "gh" + part
        return part

    def create_mailbox(self) -> tuple[str, str]:
        """Create a new email address. Returns (email, order_id).

        Mail.cx doesn't need explicit creation — the mailbox is implicit.
        We just generate the address and start polling.
        """
        localpart = self._random_localpart()
        domain = self._pick_domain()
        email = f"{localpart}@{domain}"
        self._last_email = email
        return email, email  # order_id = email (no separate order concept)

    def get_messages(self, address: str) -> list[dict]:
        """Long-poll for messages at the given address.

        GET /v1/inbox/<encoded_address>
        Returns list of message dicts or empty list.
        204 = no messages within 25s window.
        """
        from urllib.parse import quote

        encoded = quote(address, safe="")
        try:
            resp = self.session.get(
                f"{API_BASE}/inbox/{encoded}",
                headers={"Accept": "application/json"},
                timeout=30,  # long-poll can take up to 25s
            )
            if resp.status_code == 204:
                return []
            if resp.status_code == 429:
                raise MailCxError("mail.cx rate limit (429) — too many concurrent requests")
            data = resp.json()
            if isinstance(data, list):
                return data
            # Single message or wrapped response
            if isinstance(data, dict):
                if "error" in data:
                    raise MailCxError(f"mail.cx error: {data['error']}")
                if "emails" in data:
                    return data["emails"]
                if "items" in data:
                    return data["items"]
            return []
        except requests.RequestException as exc:
            raise MailCxError(f"mail.cx network error: {exc}")

    def wait_for_code(
        self,
        address: str,
        timeout: int = 240,
        poll_interval: int = 5,
        log: Optional[Callable[[str], None]] = None,
        cancel_cb: Optional[Callable[[], bool]] = None,
        email: str = "",  # ignored — present for API compat with LitensiClient
    ) -> str:
        """Poll the mailbox until the GitHub verification code arrives.

        Mail.cx long-polls for 25s per request, then we retry.
        Total timeout is controlled by `timeout` parameter.
        """
        started = time.time()
        attempts = 0

        while time.time() - started < timeout:
            if cancel_cb and cancel_cb():
                raise MailCxError("cancelled while waiting for mail")

            messages = self.get_messages(address)
            attempts += 1

            for msg in messages:
                # Extract body — check multiple fields
                body = ""
                for field in ("body", "text", "html", "content", "preview_text"):
                    val = msg.get(field, "")
                    if val:
                        body += "\n" + str(val)

                subject = msg.get("subject", "")
                from_addr = msg.get("from", msg.get("from_address", ""))

                if log:
                    log(f"[*] mailcx message from={from_addr} subject={subject[:60]}")

                code = self.extract_github_code(body)
                if code:
                    return code

            elapsed = int(time.time() - started)
            if log:
                log(f"[*] mailcx poll #{attempts} — no code yet ({elapsed}s/{timeout}s)")

            # Short sleep between polls to respect rate limits
            time.sleep(min(poll_interval, 5))

        raise MailCxError(f"no GitHub code after {timeout}s ({attempts} polls)")

    @staticmethod
    def extract_github_code(body: str) -> str:
        """Extract GitHub verification code from email body.

        GitHub sends codes in format: XXXX-XXXX (8 digits with dash).
        Falls back to other patterns.
        """
        if not body:
            return ""

        # Strip HTML tags to plain text
        plain = re.sub(r"<[^>]+>", " ", body)
        plain = re.sub(r"\s+", " ", plain).strip()

        patterns = [
            (r"(\d{4})-(\d{4})", True),        # XXXX-XXXX (GitHub style) — capture 2 groups
            (r"code\s*[:\s]\s*(\d{6,8})", False),  # code: NNNNNN
            (r">\s*(\d{6,8})\s*<", False),      # inside HTML tag
            (r"\b(\d{6,8})\b", False),           # standalone 6-8 digit
        ]

        for pat, two_groups in patterns:
            m = re.search(pat, plain, re.IGNORECASE)
            if m:
                if two_groups:
                    return m.group(1) + m.group(2)
                return m.group(1)

        return ""

    def mark_success(self, order_id: str) -> dict:
        """Confirm code was used. No-op for mail.cx (no order to confirm)."""
        return {"status": "ok", "note": "mail.cx has no order system"}

    def set_status(self, order_id: str, status: str) -> dict:
        """Set status. No-op for mail.cx."""
        return self.mark_success(order_id)

    @property
    def last_order_id(self) -> str:
        """Last email address used (acts as order_id)."""
        return self._last_email
