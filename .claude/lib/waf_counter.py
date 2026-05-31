"""
waf_counter.py — durable CloudFront/WAF 403 counter shared across agents.

Implements the trip logic from ~/.claude/CLAUDE-RULES/13-circuit-breakers.md:
  - 3 consecutive CloudFront/WAF 403 responses → trip
  - 2xx/3xx response → reset to 0
  - On trip → invoke waf-ban-handler.sh + raise SystemExit

State file: $HUNT_DIR/notes/waf-403-counter.json (file-locked).

CDN/WAF signatures detected:
  - CloudFront: X-Amz-Cf-Id, X-Cache: Error from cloudfront, Server: CloudFront
  - Akamai: Server: AkamaiGHost
  - Cloudflare: Server: cloudflare, cf-ray, error-code 1015/1020/1010
  - AWS WAF: aws-waf-token mismatch (when present in challenge)

Usage:
    from waf_counter import WafCounter
    wc = WafCounter()
    wc.observe(status_code=403, headers=resp.headers, body=resp.text)
    # raises SystemExit if 3rd consecutive

CLI:
    python3 -m waf_counter observe <status> [<header_dump>] [<body_excerpt>]
    python3 -m waf_counter reset
    python3 -m waf_counter status
"""
from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Mapping


CDN_SIGNATURES = (
    "x-amz-cf-id",
    "x-amz-cf-pop",
    "server: cloudfront",
    "server: akamaighost",
    "server: cloudflare",
    "cf-ray:",
    "request blocked",
    "error from cloudfront",
    "cloudflare ray",
    "the request could not be satisfied",
    "aws waf",
)


def _hunt_dir() -> Path:
    cfg = Path.home() / ".claude/orchestration/target.json"
    if cfg.exists():
        try:
            d = json.load(cfg.open())
            hd = d.get("meta", {}).get("hunt_dir")
            if hd and Path(hd).exists():
                return Path(hd)
        except Exception:
            pass
    return Path.home() / ".claude/orchestration"


class WafCounter:
    """Tracks consecutive CDN/WAF 403s across all agent processes."""

    def __init__(self, hunt_dir: Path | None = None, threshold: int = 3):
        self.hunt_dir = hunt_dir or _hunt_dir()
        self.threshold = threshold
        notes = self.hunt_dir / "notes"
        notes.mkdir(parents=True, exist_ok=True)
        self.path = notes / "waf-403-counter.json"

    def _read(self, fh) -> dict:
        fh.seek(0)
        raw = fh.read()
        if not raw:
            return {"consecutive_403s": 0, "total_403s_session": 0, "last_reset_ts": int(time.time())}
        try:
            return json.loads(raw)
        except Exception:
            return {"consecutive_403s": 0, "total_403s_session": 0, "last_reset_ts": int(time.time())}

    def _write(self, fh, state: dict) -> None:
        fh.seek(0)
        fh.truncate()
        fh.write(json.dumps(state))

    @staticmethod
    def is_cdn_403(status_code: int, headers: Mapping[str, str] | str, body: str) -> bool:
        if status_code != 403:
            return False
        hay = (
            (str(headers) if not isinstance(headers, str) else headers).lower()
            + " "
            + (body or "")[:2048].lower()
        )
        return any(sig in hay for sig in CDN_SIGNATURES)

    def observe(self, status_code: int, headers: Mapping[str, str] | str = "", body: str = "") -> bool:
        """Record one response. Returns True if circuit tripped."""
        with open(self.path, "a+") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            state = self._read(fh)
            if self.is_cdn_403(status_code, headers, body):
                state["consecutive_403s"] += 1
                state["total_403s_session"] += 1
            elif 200 <= status_code < 400:
                state["consecutive_403s"] = 0
            # 4xx non-403 and 5xx do NOT reset (could be application errors)
            tripped = state["consecutive_403s"] >= self.threshold
            self._write(fh, state)
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

        if tripped:
            self._trip()
        return tripped

    def _trip(self) -> None:
        handler = Path.home() / ".claude/orchestration/waf-ban-handler.sh"
        if handler.exists():
            subprocess.run(["bash", str(handler)], check=False)
        # Hard stop — every caller must propagate this.
        raise SystemExit("WAF_BANNED — see session-handoff.md, 30-min cool-down")

    def reset(self) -> None:
        with open(self.path, "a+") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            self._write(fh, {"consecutive_403s": 0, "total_403s_session": 0, "last_reset_ts": int(time.time())})
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def status(self) -> dict:
        with open(self.path, "a+") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
            state = self._read(fh)
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        return state


def _cli() -> None:
    if len(sys.argv) < 2:
        print("usage: waf_counter.py <observe|reset|status> [args]", file=sys.stderr)
        sys.exit(2)
    wc = WafCounter()
    cmd = sys.argv[1]
    if cmd == "observe":
        status = int(sys.argv[2]) if len(sys.argv) > 2 else 0
        headers = sys.argv[3] if len(sys.argv) > 3 else ""
        body = sys.argv[4] if len(sys.argv) > 4 else ""
        try:
            tripped = wc.observe(status, headers, body)
            print(json.dumps({"tripped": tripped, **wc.status()}))
            sys.exit(0 if not tripped else 99)
        except SystemExit as e:
            print(str(e), file=sys.stderr)
            sys.exit(99)
    elif cmd == "reset":
        wc.reset()
        print("reset ok")
    elif cmd == "status":
        print(json.dumps(wc.status(), indent=2))
    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    _cli()
