"""
safe_http.py — request wrapper that enforces pacing + WAF circuit + (optionally) blocks
raw HTTP to WAF-protected hosts.

Replaces direct `requests.get(...)` / `subprocess.run(["curl", ...])` for every
agent. Combines:
  - Pacer: per-domain rate limiting + global burst window (11-rate-limit-management.md)
  - WafCounter: 3-consecutive-403 circuit trip (13-circuit-breakers.md)
  - WAF-protected-host guard: deny raw curl on hosts in waf-protected-hosts.txt
    unless caller passes allow_raw=True (i.e., is going through Playwright already)

Usage:
    from safe_http import SafeHttp
    sh = SafeHttp()
    resp = sh.request("GET", "https://api.example.com/x", headers={...})
    # 'resp' is a requests.Response — or None if pre-empted by guard.

CLI wrapper:
    python3 -m safe_http GET https://target.com/path
    python3 -m safe_http POST https://target.com/path --data '{"x":1}'
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlparse

# Lazy import requests — many shell-only contexts won't have it; in that case
# we still let pacer/waf-counter run via CLI wrapper.
try:
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pacer import Pacer  # noqa: E402
from waf_counter import WafCounter  # noqa: E402


class WafProtectedHostError(RuntimeError):
    """Raised when a raw HTTP call is attempted against a WAF-protected host."""


class SafeHttp:
    def __init__(self, allow_raw_for_waf: bool = False):
        self.pacer = Pacer()
        self.waf = WafCounter()
        self.allow_raw_for_waf = allow_raw_for_waf

    def _check_waf_guard(self, url: str) -> None:
        if self.allow_raw_for_waf:
            return
        host = urlparse(url).hostname or ""
        if self.pacer.is_waf_protected(host):
            raise WafProtectedHostError(
                f"raw HTTP to WAF-protected host '{host}' is not allowed. "
                "Use Playwright (recon/login.py / recon/relogin.py) or set allow_raw_for_waf=True. "
                "Reference: ~/.claude/CLAUDE-RULES/11-rate-limit-management.md § WAF/CloudFront Protocol."
            )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        data: Any = None,
        json_body: Any = None,
        timeout: float = 20.0,
        allow_raw_for_waf: Optional[bool] = None,
        **kwargs,
    ):
        if requests is None:
            raise RuntimeError("`requests` module not available; install or use Playwright")
        if allow_raw_for_waf is not None:
            old = self.allow_raw_for_waf
            self.allow_raw_for_waf = allow_raw_for_waf
            try:
                return self.request(method, url, headers=headers, data=data,
                                    json_body=json_body, timeout=timeout, **kwargs)
            finally:
                self.allow_raw_for_waf = old

        self._check_waf_guard(url)
        host = urlparse(url).hostname or ""
        self.pacer.acquire(host)

        resp = requests.request(
            method, url, headers=dict(headers or {}),
            data=data, json=json_body, timeout=timeout, **kwargs,
        )
        # Feed WAF counter — trips raise SystemExit
        hdr_dump = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        body_excerpt = resp.text[:2048] if resp.text else ""
        self.waf.observe(resp.status_code, hdr_dump, body_excerpt)
        return resp


def _cli() -> None:
    """Minimal CLI: python3 -m safe_http GET https://host/path [--header ...] [--data ...]"""
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("method")
    p.add_argument("url")
    p.add_argument("--header", "-H", action="append", default=[])
    p.add_argument("--data", "-d", default=None)
    p.add_argument("--allow-raw", action="store_true")
    p.add_argument("--timeout", type=float, default=20.0)
    args = p.parse_args()

    hdrs = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            hdrs[k.strip()] = v.strip()

    sh = SafeHttp(allow_raw_for_waf=args.allow_raw)
    try:
        r = sh.request(args.method, args.url, headers=hdrs, data=args.data, timeout=args.timeout)
    except WafProtectedHostError as e:
        print(f"DENIED: {e}", file=sys.stderr)
        sys.exit(40)
    except SystemExit:
        # WAF circuit tripped
        sys.exit(99)
    print(f"HTTP/{r.status_code}")
    for k, v in r.headers.items():
        print(f"{k}: {v}")
    print()
    print(r.text[:4096])


if __name__ == "__main__":
    _cli()
