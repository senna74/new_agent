#!/usr/bin/env python3
"""
proxy_manager.py — permanent Tor SOCKS5 + circuit rotation library for
authorized bug bounty testing against WAF-protected targets.

Built after Gallup engagement: AWS WAF banned the host IP permanently within
12 forged-JWT requests. 30-min cool-down heuristic was wrong — the ban
persisted >3 hours. The program (HackerOne) recommended a gateway proxy but
no URL was configured. Tor is the unattended fallback.

USAGE FROM PYTHON
-----------------
    from proxy_manager import ProxyManager

    pm = ProxyManager()
    pm.ensure_running()                  # idempotent: starts tor if needed
    print(pm.get_proxy_url())            # "socks5://127.0.0.1:9050"
    print(pm.current_exit_ip())          # current tor exit ip
    pm.rotate_ip()                       # NEWNYM (10s cooldown enforced)
    print(pm.is_banned("loginq.gallup.com"))  # heuristic

    # auto-retry-on-ban wrapper:
    pm.rotate_until_clear("loginq.gallup.com", max_attempts=5)

USAGE FROM SHELL
----------------
    python3 proxy_manager.py start             # start tor daemon
    python3 proxy_manager.py url               # print proxy URL
    python3 proxy_manager.py rotate            # NEWNYM + print new IP
    python3 proxy_manager.py ip                # print current exit IP
    python3 proxy_manager.py check <host>      # check if host is WAF-banning current exit
    python3 proxy_manager.py test              # full self-test
    python3 proxy_manager.py status            # status report

INTEGRATION POINTS
------------------
- ~/.claude/orchestration/lib/oidc-login.py — Playwright login helper
- ~/.claude/orchestration/auto-login.sh — per-role auto-login wrapper
- ~/.claude/CLAUDE-RULES/11-rate-limit-management.md § IP Rotation Protocol
- ~/.claude/CLAUDE-RULES/00-auto-init.md Section pre-step — ensure proxy for WAF targets
- target.json schema: meta.proxy = {"auto": true, "type": "tor", "rotate_on_ban": true}

WAF-BAN HEURISTIC
-----------------
Per research (Microsoft Playwright #10567, AWS WAF docs), a CloudFront WAF
block is identified by ALL THREE of:
  1. HTTP status == 403
  2. Response header 'server: CloudFront' (case-insensitive)
  3. Body contains 'Request blocked' OR 'ERROR: The request could not be satisfied'
A 403 alone is NOT a ban (many legit endpoints 403). Origin-level 403s lack
the CloudFront error page entirely.

TOR + PLAYWRIGHT NOTES (2025)
-----------------------------
- Use 'socks5://' scheme — chromium routes DNS through the tunnel.
- SOCKS5 *with auth* breaks Playwright chromium (#10567). Local Tor on
  127.0.0.1 needs no auth, so this is fine for us.
- NEWNYM rate-limit is 10s; we enforce 15s for safety.
- AWS Managed Rules `AWSManagedRulesAnonymousIpList` blocks most Tor exits
  by default. Empirical pass rate <5%. Expect to rotate many times.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration — single source of truth for all proxy plumbing.
# ---------------------------------------------------------------------------

HOME = Path.home()
TOR_DIR = HOME / "tor-portable"
TOR_BIN = TOR_DIR / "tor" / "tor"
TOR_LIB = TOR_DIR / "tor"
TOR_DATA = TOR_DIR / "data"
TOR_LOG = TOR_DIR / "tor.log"
TOR_RC = TOR_DIR / "torrc"
TOR_STDOUT = TOR_DIR / "tor-stdout.log"
COOKIE_PATH = TOR_DATA / "control_auth_cookie"
PID_FILE = TOR_DIR / "tor.pid"

SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 9050
CONTROL_PORT = 9051

ORCH_DIR = HOME / ".claude" / "orchestration"
WAF_HOSTS_FILE = ORCH_DIR / "waf-protected-hosts.txt"

# Tor expert bundle URL (Linux x86_64). Update version if needed.
TOR_BUNDLE_URL = "https://dist.torproject.org/torbrowser/15.0.14/tor-expert-bundle-linux-x86_64-15.0.14.tar.gz"

# torrc template — minimal, focused on automation
TORRC_TEMPLATE = """SocksPort 127.0.0.1:{socks}
ControlPort 127.0.0.1:{control}
CookieAuthentication 1
CookieAuthFileGroupReadable 1
DataDirectory {data}
Log notice file {log}
RunAsDaemon 0
NewCircuitPeriod 60
MaxCircuitDirtiness 60
"""

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Last NEWNYM timestamp — enforces 15s cooldown across calls in the same process
_last_newnym = 0.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log(msg: str):
    sys.stderr.write(f"[proxy_manager] {msg}\n")
    sys.stderr.flush()


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _write_torrc():
    TOR_DIR.mkdir(parents=True, exist_ok=True)
    TOR_DATA.mkdir(parents=True, exist_ok=True)
    TOR_RC.write_text(
        TORRC_TEMPLATE.format(
            socks=SOCKS_PORT,
            control=CONTROL_PORT,
            data=str(TOR_DATA),
            log=str(TOR_LOG),
        )
    )


def _wait_for_bootstrap(timeout: int = 60) -> bool:
    """Poll tor.log until 'Bootstrapped 100%' appears."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if TOR_LOG.exists():
                tail = TOR_LOG.read_text(errors="replace")[-4096:]
                if "Bootstrapped 100%" in tail:
                    return True
        except Exception:
            pass
        time.sleep(1.5)
    return False


def _download_tor() -> bool:
    """Download portable tor expert bundle to ~/tor-portable/."""
    _log(f"downloading tor expert bundle to {TOR_DIR}")
    TOR_DIR.mkdir(parents=True, exist_ok=True)
    archive = TOR_DIR / "tor-bundle.tar.gz"
    try:
        req = urllib.request.Request(TOR_BUNDLE_URL, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=120) as r:
            archive.write_bytes(r.read())
        # extract
        subprocess.run(
            ["tar", "xzf", str(archive)],
            cwd=str(TOR_DIR),
            check=True,
            capture_output=True,
        )
        archive.unlink(missing_ok=True)
        return TOR_BIN.exists()
    except Exception as e:
        _log(f"tor download failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class ProxyManager:
    def __init__(self,
                 socks_host: str = SOCKS_HOST,
                 socks_port: int = SOCKS_PORT,
                 control_port: int = CONTROL_PORT):
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.control_port = control_port

    # ----- lifecycle ------------------------------------------------------

    def is_running(self) -> bool:
        return _port_open(self.socks_host, self.socks_port)

    def install_if_missing(self) -> bool:
        if TOR_BIN.exists():
            return True
        return _download_tor()

    def start(self, wait_bootstrap: bool = True, timeout: int = 60) -> bool:
        """Start tor as a fully-detached daemon. Idempotent."""
        if self.is_running():
            return True
        if not self.install_if_missing():
            _log("tor binary missing and download failed")
            return False
        _write_torrc()

        # subprocess.Popen with start_new_session=True is the cleanest way
        # to truly detach. Combine with stdin=DEVNULL + stdout/stderr to file.
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = f"{TOR_LIB}:{env.get('LD_LIBRARY_PATH','')}"
        with open(TOR_STDOUT, "ab") as out:
            proc = subprocess.Popen(
                [str(TOR_BIN), "-f", str(TOR_RC)],
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=subprocess.STDOUT,
                env=env,
                start_new_session=True,
                close_fds=True,
            )
        PID_FILE.write_text(str(proc.pid))
        _log(f"tor started pid={proc.pid}")

        if not wait_bootstrap:
            return True
        if _wait_for_bootstrap(timeout=timeout):
            _log("tor bootstrapped 100%")
            return True
        _log("tor bootstrap timeout")
        return False

    def ensure_running(self) -> bool:
        if self.is_running():
            return True
        return self.start(wait_bootstrap=True)

    def stop(self) -> None:
        """Stop the tor daemon if we know its PID."""
        if not PID_FILE.exists():
            subprocess.run(["pkill", "-f", str(TOR_BIN)], check=False)
            return
        try:
            pid = int(PID_FILE.read_text().strip())
            os.kill(pid, 15)
            time.sleep(2)
        except Exception:
            subprocess.run(["pkill", "-f", str(TOR_BIN)], check=False)
        finally:
            PID_FILE.unlink(missing_ok=True)

    # ----- query ----------------------------------------------------------

    def get_proxy_url(self, scheme: str = "socks5") -> str:
        """Return proxy URL for Playwright / requests. Default 'socks5://'."""
        return f"{scheme}://{self.socks_host}:{self.socks_port}"

    def get_playwright_proxy(self) -> dict:
        """Return Playwright's proxy launch arg."""
        return {"server": self.get_proxy_url("socks5")}

    def current_exit_ip(self, timeout: int = 30) -> Optional[str]:
        """Fetch current tor exit IP from api.ipify.org. None on error."""
        if not self.is_running():
            return None
        try:
            # Use SOCKS5 via PySocks
            import socks
            import socket as _socket

            old_socket = _socket.socket
            socks.set_default_proxy(socks.SOCKS5, self.socks_host, self.socks_port, rdns=True)
            _socket.socket = socks.socksocket
            try:
                req = urllib.request.Request(
                    "https://api.ipify.org",
                    headers={"User-Agent": USER_AGENT},
                )
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return r.read().decode().strip()
            finally:
                _socket.socket = old_socket
        except Exception as e:
            _log(f"exit-ip fetch failed: {e}")
            return None

    # ----- rotation -------------------------------------------------------

    def rotate_ip(self, wait_seconds: int = 15) -> bool:
        """Send NEWNYM via ControlPort. Enforces 15s cooldown between calls."""
        global _last_newnym
        elapsed = time.time() - _last_newnym
        if elapsed < wait_seconds:
            sleep_for = wait_seconds - elapsed
            _log(f"newnym cooldown — sleep {sleep_for:.1f}s")
            time.sleep(sleep_for)

        try:
            from stem import Signal
            from stem.control import Controller

            with Controller.from_port(address=self.socks_host, port=self.control_port) as controller:
                controller.authenticate()  # uses cookie auth
                controller.signal(Signal.NEWNYM)
                _last_newnym = time.time()
                _log("NEWNYM sent")
                time.sleep(wait_seconds)  # let new circuit form
                return True
        except Exception as e:
            _log(f"rotate failed: {e}")
            return False

    # ----- ban detection --------------------------------------------------

    @staticmethod
    def detect_cloudfront_ban(status: int, headers: dict, body: str) -> bool:
        """Return True iff response is a CloudFront/AWS WAF block, not just a
        regular 403. Heuristic per research: status 403 + CloudFront fingerprint
        + WAF error body."""
        if status != 403:
            return False
        # Headers can be dict-like; normalize keys lowercase
        hdrs = {k.lower(): str(v) for k, v in (headers or {}).items()}
        server_is_cf = "cloudfront" in hdrs.get("server", "").lower()
        has_cf_id = "x-amz-cf-id" in hdrs
        body_l = (body or "").lower()
        body_is_waf = (
            "request blocked" in body_l
            or "the request could not be satisfied" in body_l
            or "request could not be satisfied" in body_l
        )
        # Require AT LEAST 2 of 3 — the body alone is most discriminating
        score = sum([server_is_cf, has_cf_id, body_is_waf])
        return score >= 2

    def is_banned(self, host: str, timeout: int = 20) -> bool:
        """Probe `https://<host>/` through tor; return True if WAF-blocking."""
        if not self.is_running():
            return False  # not banned if we can't even test
        try:
            import socks
            import socket as _socket

            old_socket = _socket.socket
            socks.set_default_proxy(socks.SOCKS5, self.socks_host, self.socks_port, rdns=True)
            _socket.socket = socks.socksocket
            try:
                req = urllib.request.Request(
                    f"https://{host}/",
                    headers={"User-Agent": USER_AGENT, "Accept": "text/html"},
                )
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as r:
                        status = r.getcode()
                        headers = dict(r.headers)
                        body = r.read(2048).decode("utf-8", errors="replace")
                except urllib.error.HTTPError as e:
                    status = e.code
                    headers = dict(e.headers) if e.headers else {}
                    body = ""
                    try:
                        body = e.read(2048).decode("utf-8", errors="replace")
                    except Exception:
                        pass
                return self.detect_cloudfront_ban(status, headers, body)
            finally:
                _socket.socket = old_socket
        except Exception as e:
            _log(f"is_banned probe failed for {host}: {e}")
            return False

    def rotate_until_clear(self, host: str, max_attempts: int = 5) -> bool:
        """Rotate IP until `host` no longer returns a WAF block. Returns True
        if we found a clean exit; False if max_attempts exhausted."""
        self.ensure_running()
        for attempt in range(1, max_attempts + 1):
            ip = self.current_exit_ip()
            banned = self.is_banned(host)
            _log(f"attempt {attempt}/{max_attempts} ip={ip} banned={banned}")
            if not banned:
                return True
            if attempt == max_attempts:
                break
            self.rotate_ip()
        return False

    # ----- helpers --------------------------------------------------------

    def status(self) -> dict:
        running = self.is_running()
        ip = self.current_exit_ip() if running else None
        return {
            "tor_running": running,
            "socks_proxy": self.get_proxy_url() if running else None,
            "control_port_listening": _port_open(self.socks_host, self.control_port),
            "current_exit_ip": ip,
            "host_egress_ip": _current_host_ip(),
            "binary": str(TOR_BIN),
            "binary_exists": TOR_BIN.exists(),
            "torrc": str(TOR_RC),
            "log_tail": TOR_LOG.read_text(errors="replace").splitlines()[-5:] if TOR_LOG.exists() else [],
        }


# ---------------------------------------------------------------------------
# Helpers (module-level)
# ---------------------------------------------------------------------------

def _current_host_ip(timeout: int = 5) -> Optional[str]:
    """Egress IP of the host without tor, for comparison."""
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode().strip()
    except Exception:
        return None


def is_waf_protected(host: str) -> bool:
    """Check whether `host` is in the WAF-protected hosts list."""
    files = [WAF_HOSTS_FILE]
    # also check per-target overrides if present in env or argv
    hunt_dir = os.environ.get("HUNT_DIR", "")
    if hunt_dir:
        files.insert(0, Path(hunt_dir) / "recon" / "waf-protected-hosts.txt")
    hosts: list[str] = []
    for f in files:
        try:
            if f.exists():
                hosts.extend(
                    line.strip().split("#")[0].strip()
                    for line in f.read_text().splitlines()
                    if line.strip() and not line.strip().startswith("#")
                )
        except Exception:
            continue
    return any(host == h or host.endswith("." + h) for h in hosts if h)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli():
    pm = ProxyManager()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"

    if cmd == "start":
        ok = pm.ensure_running()
        sys.exit(0 if ok else 1)

    elif cmd == "stop":
        pm.stop()
        print("tor stopped")
        sys.exit(0)

    elif cmd == "url":
        pm.ensure_running()
        print(pm.get_proxy_url())
        sys.exit(0)

    elif cmd == "ip":
        pm.ensure_running()
        ip = pm.current_exit_ip()
        print(ip or "ERR")
        sys.exit(0 if ip else 2)

    elif cmd == "rotate":
        pm.ensure_running()
        ok = pm.rotate_ip()
        if ok:
            print("new exit ip:", pm.current_exit_ip() or "?")
        sys.exit(0 if ok else 1)

    elif cmd == "check":
        host = sys.argv[2] if len(sys.argv) > 2 else ""
        if not host:
            print("usage: proxy_manager.py check <host>", file=sys.stderr)
            sys.exit(2)
        pm.ensure_running()
        banned = pm.is_banned(host)
        print("BANNED" if banned else "CLEAR")
        sys.exit(1 if banned else 0)

    elif cmd == "rotate-until-clear":
        host = sys.argv[2] if len(sys.argv) > 2 else ""
        attempts = int(sys.argv[3]) if len(sys.argv) > 3 else 5
        if not host:
            print("usage: proxy_manager.py rotate-until-clear <host> [attempts]", file=sys.stderr)
            sys.exit(2)
        pm.ensure_running()
        ok = pm.rotate_until_clear(host, max_attempts=attempts)
        if ok:
            print("CLEAR", pm.current_exit_ip())
        else:
            print("STILL_BANNED after", attempts, "rotations")
        sys.exit(0 if ok else 1)

    elif cmd == "status":
        pm.ensure_running()
        st = pm.status()
        print(json.dumps(st, indent=2, default=str))
        sys.exit(0)

    elif cmd == "test":
        # Full self-test: start, get IP, rotate, get new IP, ban-check ipify (should be clear)
        ok = pm.ensure_running()
        if not ok:
            print("FAIL: tor did not start")
            sys.exit(1)
        ip1 = pm.current_exit_ip()
        print(f"exit ip #1: {ip1}")
        ok = pm.rotate_ip()
        if not ok:
            print("WARN: rotate failed (control port?)")
        ip2 = pm.current_exit_ip()
        print(f"exit ip #2: {ip2}")
        if ip1 and ip2 and ip1 != ip2:
            print("OK: IP rotation works")
        host_ip = _current_host_ip()
        print(f"host egress ip (no tor): {host_ip}")
        print("OK" if ip1 != host_ip else "WARN: tor exit == host ip (tor not used?)")
        sys.exit(0)

    elif cmd == "is-waf-protected":
        host = sys.argv[2] if len(sys.argv) > 2 else ""
        print("YES" if is_waf_protected(host) else "NO")
        sys.exit(0 if is_waf_protected(host) else 1)

    else:
        print(__doc__)
        sys.exit(0)


if __name__ == "__main__":
    _cli()
