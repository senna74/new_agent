"""
pacer.py — per-domain rate limiter with cross-process file locking.

Implements the policy from ~/.claude/CLAUDE-RULES/11-rate-limit-management.md:
  - Default: max 2 req/s per domain (token bucket)
  - WAF-protected: max 1 req/3 sec per domain, max 20 req/60 sec global
  - Burst race: opt-in via env or call kwarg

Cross-process sharing: state is persisted to a JSON file under
$HUNT_DIR/recon/.rate-state.json, protected by fcntl.LOCK_EX. Every
agent process (curl wrapper, Playwright, nuclei adapter) calls
Pacer.acquire(domain) before issuing a request.

Usage:
    from pacer import Pacer
    pacer = Pacer()           # auto-loads policy from target.json
    pacer.acquire("loginq.gallup.com")
    # ... make HTTP request ...

Or as a one-liner from bash:
    python3 -m pacer acquire loginq.gallup.com
"""
from __future__ import annotations

import fcntl
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict


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


def _state_path() -> Path:
    p = _hunt_dir() / "recon" / ".rate-state.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


class Pacer:
    """Per-domain token-bucket pacer with cross-process file locking."""

    DEFAULT_RPS = 2.0           # safe baseline per 11-rate-limit-management.md
    WAF_PROTECTED_INTERVAL = 3.0  # seconds between requests to WAF-protected hosts
    GLOBAL_BURST_WINDOW = 60.0    # seconds
    GLOBAL_BURST_MAX = 20         # max requests within window (WAF-protected)

    def __init__(self, hunt_dir: Path | None = None):
        self.hunt_dir = hunt_dir or _hunt_dir()
        self.state_file = _state_path()
        # Load WAF-protected host list (one host per line)
        self.waf_hosts = self._load_waf_hosts()

    def _load_waf_hosts(self) -> set[str]:
        p = self.hunt_dir / "recon" / "waf-protected-hosts.txt"
        if not p.exists():
            # Fall back to global list
            p = Path.home() / ".claude/orchestration/waf-protected-hosts.txt"
        if not p.exists():
            return set()
        return {ln.strip() for ln in p.read_text().splitlines() if ln.strip() and not ln.startswith("#")}

    def is_waf_protected(self, domain: str) -> bool:
        dom = domain.lower()
        for h in self.waf_hosts:
            if dom == h.lower() or dom.endswith("." + h.lower()):
                return True
        return False

    def _read_state(self, fh) -> Dict:
        fh.seek(0)
        raw = fh.read()
        if not raw:
            return {"last_per_domain": {}, "global_requests": []}
        try:
            return json.loads(raw)
        except Exception:
            return {"last_per_domain": {}, "global_requests": []}

    def _write_state(self, fh, state: Dict) -> None:
        fh.seek(0)
        fh.truncate()
        fh.write(json.dumps(state))

    def acquire(self, domain: str) -> float:
        """Block until a request to `domain` is allowed. Returns waited seconds."""
        is_waf = self.is_waf_protected(domain)
        interval = self.WAF_PROTECTED_INTERVAL if is_waf else (1.0 / self.DEFAULT_RPS)

        slept = 0.0
        while True:
            with open(self.state_file, "a+") as fh:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                state = self._read_state(fh)
                now = time.time()

                # Per-domain gate
                last = state["last_per_domain"].get(domain, 0.0)
                wait_dom = max(0.0, last + interval - now)

                # Global gate (WAF only)
                wait_glob = 0.0
                if is_waf:
                    state["global_requests"] = [
                        t for t in state["global_requests"]
                        if now - t < self.GLOBAL_BURST_WINDOW
                    ]
                    if len(state["global_requests"]) >= self.GLOBAL_BURST_MAX:
                        oldest = state["global_requests"][0]
                        wait_glob = max(0.0, oldest + self.GLOBAL_BURST_WINDOW - now)

                wait = max(wait_dom, wait_glob)
                if wait <= 0:
                    state["last_per_domain"][domain] = now
                    if is_waf:
                        state["global_requests"].append(now)
                    self._write_state(fh, state)
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                    return slept
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

            # Sleep outside the lock so other processes can make progress.
            time.sleep(min(wait, 5.0))
            slept += min(wait, 5.0)


def _cli_main() -> None:
    if len(sys.argv) < 2:
        print("usage: pacer.py <acquire|status> <domain>", file=sys.stderr)
        sys.exit(2)
    cmd = sys.argv[1]
    pacer = Pacer()
    if cmd == "acquire":
        if len(sys.argv) < 3:
            print("acquire requires <domain>", file=sys.stderr)
            sys.exit(2)
        waited = pacer.acquire(sys.argv[2])
        if waited > 0:
            print(f"[pacer] waited {waited:.2f}s for {sys.argv[2]}", file=sys.stderr)
        sys.exit(0)
    elif cmd == "status":
        with open(pacer.state_file, "a+") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
            state = pacer._read_state(fh)
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        print(json.dumps(state, indent=2))
        sys.exit(0)
    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    _cli_main()
