"""
oidc-login.py — generic two-stage OIDC / IdentityServer4 Playwright login.

Drives the username → password → OIDC callback flow that IdentityServer4,
ADFS, Okta, Auth0, OneLogin and most modern IdPs share. Designed as the
fallback when auto-login.sh's JSON POST returns nothing useful.

What it handles:
  - Anti-bot Chromium flags (--disable-blink-features=AutomationControlled,
    realistic UA, viewport, no legacy headless).
  - Two-stage form: username on one page, password on the next.
  - First-login interstitials: security-questions enrollment, accept-cookies
    banners, "ACCEPT ALL" buttons.
  - JWT capture from /connect/token JSON, OIDC code from /connect/authorize
    callback, AND any eyJ... embedded in page text/URLs.
  - All cookies persisted to tokens.json under accounts.<ROLE>.session_cookies.

Usage:
  python3 ~/.claude/orchestration/lib/oidc-login.py <ROLE> [<START_URL>]

Reads target.json for credentials. Honors HTTP_PROXY / HTTPS_PROXY env vars.
Writes to {HUNT_DIR}/recon/tokens.json atomically.

Designed to be reused by:
  - ~/.claude/orchestration/auto-login.sh (called as final fallback)
  - per-target login.py / relogin.py (can `from oidc_login import ...`)
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.parse
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright
except Exception:
    print("ERR: playwright not installed. Run: pip install playwright && playwright install chromium", file=sys.stderr)
    sys.exit(2)


JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

# Username/password input selectors — ordered most-specific to most-general.
USERNAME_SELECTORS = [
    'input[type=email]',
    'input[name=username]', 'input[name=Username]', 'input[name=UserName]',
    'input[name="Input.Username"]', 'input[name="Input.Email"]',
    'input[id=username]', 'input[id=Username]', 'input[id=Email]',
    'input[autocomplete=username]',
]
PASSWORD_SELECTORS = [
    'input[type=password]',
    'input[name=password]', 'input[name=Password]',
    'input[name="Input.Password"]',
    'input[autocomplete=current-password]',
]
SUBMIT_SELECTORS = [
    'button[type=submit]',
    'input[type=submit]',
    'button:has-text("Next")', 'button:has-text("Continue")',
    'button:has-text("Sign In")', 'button:has-text("Log In")',
    'button:has-text("SIGN IN")', 'button:has-text("LOG IN")',
    '#nextButton', '#loginButton', '#signInButton',
]
COOKIE_ACCEPT_SELECTORS = [
    'button:has-text("ACCEPT ALL")',
    'button:has-text("Accept All")',
    'button:has-text("Accept all cookies")',
    'button:has-text("I agree")',
    '#onetrust-accept-btn-handler',
]


def hunt_dir() -> Path:
    cfg = Path.home() / ".claude/orchestration/target.json"
    return Path(json.load(cfg.open())["meta"]["hunt_dir"])


def load_config() -> dict:
    cfg = Path.home() / ".claude/orchestration/target.json"
    return json.load(cfg.open())


def atomic_update_tokens(role: str, fields: dict) -> None:
    tok = hunt_dir() / "recon/tokens.json"
    tok.parent.mkdir(parents=True, exist_ok=True)
    if tok.exists() and tok.stat().st_size > 1:
        try:
            data = json.load(tok.open())
        except Exception:
            data = {}
    else:
        data = {}
    data.setdefault(role, {})
    data[role].update(fields)
    tmp = tok.with_suffix(".json.tmp")
    with tmp.open("w") as f:
        json.dump(data, f, indent=2)
    tmp.replace(tok)


def try_first(page, selectors: list[str], action: str, value: str | None = None, timeout: int = 4000):
    last_err = None
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            loc.wait_for(state="visible", timeout=timeout)
            if action == "fill":
                loc.fill(value)
            elif action == "click":
                loc.click()
            return sel
        except Exception as e:
            last_err = e
            continue
    return None


def handle_security_questions(page, log) -> bool:
    """Auto-enroll if redirected to SecurityQuestions page. Returns True on success."""
    if "SecurityQuestion" not in page.url:
        return False
    log("security-questions enrollment detected")
    # Wait for the selects to actually become enabled.
    selects = page.locator("select")
    n = selects.count()
    if n == 0:
        log("no <select> on SQ page — skipping")
        return False
    for i in range(n):
        sel = selects.nth(i)
        try:
            sel.wait_for(state="visible", timeout=5000)
            # Wait until the first non-empty option is selectable
            page.wait_for_function(
                "(el) => el.options && Array.from(el.options).some(o => o.value && !o.disabled)",
                arg=sel.element_handle(),
                timeout=15000,
            )
            opts = sel.evaluate(
                "(el) => Array.from(el.options).filter(o => o.value && !o.disabled).map(o => o.value)"
            )
            if opts:
                sel.select_option(opts[0])
                log(f"select[{i}] picked {opts[0]}")
        except Exception as e:
            log(f"select[{i}] fill err: {e}")
    # Fill any visible text inputs (answers).
    inputs = page.locator('input[type=text], input:not([type])')
    cnt = inputs.count()
    for i in range(cnt):
        try:
            inp = inputs.nth(i)
            if inp.is_visible():
                inp.fill("answer1234")
        except Exception:
            pass
    # Click submit (try common IDs).
    for sel in ('#completeSetupSubmitFormButton', 'button[type=submit]', 'button:has-text("SUBMIT")'):
        try:
            page.locator(sel).first.click(timeout=4000)
            log(f"SQ submitted via {sel}")
            return True
        except Exception:
            continue
    return False


def login(role: str, start_url: str | None = None) -> int:
    cfg = load_config()
    acct = cfg["accounts"][role]
    user = acct["username"]
    pwd = acct["password"]
    dash = cfg["urls"].get("dashboard", "")
    start_url = start_url or (acct.get("login_url") or dash or "https://" + cfg["scope"]["domains"][0])

    log_path = hunt_dir() / "recon" / "oidc-login.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(msg: str):
        line = f"[{time.strftime('%H:%M:%S')}] {role} {msg}"
        print(line, flush=True)
        with log_path.open("a") as f:
            f.write(line + "\n")

    captured = {"id_token": None, "access_token": None, "code": None, "all_jwts": []}

    def grab(text: str | None):
        if not text:
            return
        for m in JWT_RE.findall(text):
            if m not in captured["all_jwts"]:
                captured["all_jwts"].append(m)

    # Resolve proxy in priority order:
    #   1. HTTPS_PROXY / HTTP_PROXY env var (operator override / gateway URL)
    #   2. If target start_url's host is in waf-protected-hosts.txt, auto-start
    #      Tor via proxy_manager and use its SOCKS5 URL.
    proxy_url = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
    if not proxy_url:
        try:
            sys.path.insert(0, str(Path.home() / ".claude/orchestration/lib"))
            from proxy_manager import ProxyManager, is_waf_protected  # type: ignore
            host = urllib.parse.urlparse(start_url).hostname or ""
            if host and is_waf_protected(host):
                pm = ProxyManager()
                if pm.ensure_running():
                    proxy_url = pm.get_proxy_url()
                    log(f"auto-started tor proxy for WAF-protected host {host}")
                    # Rotate until exit IP is not banned (or max 5 tries)
                    if pm.rotate_until_clear(host, max_attempts=5):
                        log(f"tor exit clear for {host}: {pm.current_exit_ip()}")
                    else:
                        log(f"warning: all 5 tor exits banned for {host} — proceeding anyway")
        except Exception as e:
            log(f"proxy_manager unavailable: {e}")

    launch_kw = {"headless": True, "args": ["--no-sandbox", "--disable-blink-features=AutomationControlled"]}
    ctx_kw = {
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "viewport": {"width": 1280, "height": 800},
    }
    if proxy_url:
        u = urllib.parse.urlparse(proxy_url if "://" in proxy_url else f"http://{proxy_url}")
        launch_kw["proxy"] = {"server": f"{u.scheme}://{u.hostname}:{u.port or 8080}"}
        if u.username:
            launch_kw["proxy"]["username"] = urllib.parse.unquote(u.username)
        if u.password:
            launch_kw["proxy"]["password"] = urllib.parse.unquote(u.password)
        log(f"proxy: {launch_kw['proxy']['server']}")

    with sync_playwright() as p:
        browser = p.chromium.launch(**launch_kw)
        ctx = browser.new_context(**ctx_kw)
        page = ctx.new_page()

        def on_response(resp):
            try:
                u = resp.url
                if "/connect/token" in u:
                    body = resp.text()
                    grab(body)
                    try:
                        j = json.loads(body)
                        for k in ("id_token", "access_token", "refresh_token"):
                            if isinstance(j.get(k), str):
                                captured[k] = j[k]
                    except Exception:
                        pass
                elif "/connect/authorize" in u:
                    grab(u)
                    try:
                        grab(resp.text())
                    except Exception:
                        pass
            except Exception:
                pass

        page.on("response", on_response)

        log(f"navigating to {start_url}")
        page.goto(start_url, wait_until="domcontentloaded", timeout=30000)

        # Dismiss cookie banner if present
        for sel in COOKIE_ACCEPT_SELECTORS:
            try:
                page.locator(sel).first.click(timeout=1500)
                log(f"cookie banner dismissed via {sel}")
                break
            except Exception:
                continue

        # Stage 1 — username
        used = try_first(page, USERNAME_SELECTORS, "fill", user, timeout=8000)
        log(f"username filled via {used}")
        try_first(page, SUBMIT_SELECTORS, "click", timeout=4000)
        try:
            page.wait_for_load_state("networkidle", timeout=10000)
        except Exception:
            pass

        # Stage 2 — password
        used = try_first(page, PASSWORD_SELECTORS, "fill", pwd, timeout=8000)
        log(f"password filled via {used}")
        try_first(page, SUBMIT_SELECTORS, "click", timeout=4000)
        try:
            page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass

        # Handle SQ enrollment (post-login interstitial)
        handled = handle_security_questions(page, log)
        if handled:
            try:
                page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass

        # Capture final state
        cookies = {c["name"]: c["value"] for c in ctx.cookies()}
        grab(page.url)
        try:
            grab(page.content())
        except Exception:
            pass

        primary_jwt = captured["access_token"] or (captured["all_jwts"][-1] if captured["all_jwts"] else "")
        fields = {
            "username": user,
            "password": pwd,
            "obtained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "session_cookies": cookies,
            "all_jwts": captured["all_jwts"],
        }
        # tokens.json standardized field name is `jwt` (per auto-login.sh).
        # Preserve id_token as a separate slot (distinct OIDC claim); access_token
        # is collapsed into `jwt` to avoid name drift across the codebase.
        if captured["id_token"]:
            fields["id_token"] = captured["id_token"]
        if primary_jwt:
            fields["jwt"] = primary_jwt
        atomic_update_tokens(role, fields)

        log(f"final url = {page.url}")
        log(f"saved tokens. jwts={len(captured['all_jwts'])} cookies={len(cookies)}")

        browser.close()
        return 0 if (primary_jwt or cookies) else 1


def main():
    role = sys.argv[1] if len(sys.argv) > 1 else "ADMIN"
    start_url = sys.argv[2] if len(sys.argv) > 2 else None
    sys.exit(login(role, start_url))


if __name__ == "__main__":
    main()
