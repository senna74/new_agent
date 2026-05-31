#!/usr/bin/env python3
"""Inspect /p/<token> + /public/dashboard/<token> behavior and metadata leak."""
import sys, os, json, time
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp

sh = SafeHttp(allow_raw_for_waf=True)
TOK = json.load(open('/home/hunter/new_agent/targets/mixpanel/recon/tokens.json'))

def H(role, extra=None):
    h = dict(TOK[role]['api_request_headers'])
    h["User-Agent"] = "Mozilla/5.0"
    h["Accept"] = "application/json"
    h["X-Requested-With"] = "XMLHttpRequest"
    h["Origin"] = "https://mixpanel.com"
    if extra: h.update(extra)
    return h

BASE = "https://mixpanel.com"
LOG = open('/home/hunter/new_agent/results/mixpanel/probe_share7_log.txt', 'w')
def log(msg):
    print(msg); LOG.write(msg+"\n"); LOG.flush()

# 1. Inspect token structure of the recon-collected /p/<token> shorts
import base64, binascii, string
short_tokens = [
    "2cv24kB3k5n9reXr9bSJKU",
    "5dbqyToAtFMaDJVJNzUeuG",
    "BkaDwovdEpEcMJp33R6sah",
    "CEngFwLvPa5zvTSLvFTHNH",
    "MKDgQSoYBZciN4AGgY7Mgh",
    "QLBHa24vdYuK2MJLiNUA1S",
]
log("=== Token analysis ===")
for t in short_tokens:
    log(f"  token={t} len={len(t)}")
    # try base58 chars (no 0OIl); these strings include 0/O/I/l? check
    used = set(t)
    base58_alphabet = set(string.ascii_letters + string.digits) - set("0OIl")
    in_b58 = used.issubset(base58_alphabet)
    in_b64url = used.issubset(set(string.ascii_letters + string.digits + "-_"))
    in_b64 = used.issubset(set(string.ascii_letters + string.digits + "+/="))
    log(f"    chars={''.join(sorted(used))} b58_alphabet={in_b58} b64url={in_b64url} b64={in_b64}")
    # base64 decode try (urlsafe + padding)
    for pad in ['', '=', '==']:
        for fn, name in [(base64.urlsafe_b64decode, 'b64url'), (base64.b64decode, 'b64')]:
            try:
                raw = fn(t + pad)
                if len(raw) >= 12:
                    log(f"    {name}+pad{len(pad)} hex={raw.hex()} len={len(raw)}")
                break
            except Exception:
                pass
        else:
            continue
        break

# 2. Decode as Base58 (Bitcoin alphabet) — many SaaS use base58 for IDs
import sys as _sys
b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58decode(s):
    n = 0
    for c in s:
        if c not in b58_alphabet:
            return None
        n = n * 58 + b58_alphabet.index(c)
    h = hex(n)[2:].rstrip('L')
    if len(h) % 2: h = '0'+h
    return bytes.fromhex(h)

log("=== Base58 decode ===")
for t in short_tokens:
    raw = b58decode(t)
    if raw is not None:
        log(f"  {t} -> b58 hex={raw.hex()} len={len(raw)}")
    else:
        log(f"  {t} -> NOT base58")

# 3. Inspect the /p/<token> response fully — capture full HTML to a file for analysis
for t in short_tokens[:1]:
    try:
        r = sh.request("GET", f"{BASE}/p/{t}", headers={"User-Agent":"Mozilla/5.0"})
        log(f"GET /p/{t} (no auth) -> {r.status_code} ct={r.headers.get('Content-Type','')[:50]} body_len={len(r.text)}")
        with open(f'/home/hunter/new_agent/results/mixpanel/p_{t}.html','w') as f:
            f.write(r.text)
        # extract metadata leak hints
        text = r.text
        for hint in ['eng-accounts@mixpanel.com', 'project_id', 'organization_id', 'creator_email', '"creator":', 'csrftoken', 'sessionid', 'api_key', 'token', 'window.MP', '__NEXT_DATA__', 'getMP', 'INITIAL_STATE', 'dashboard_id']:
            if hint in text:
                idx = text.find(hint)
                log(f"    HIT '{hint}' at {idx}: ...{text[max(0,idx-30):idx+150]!r}...")
    except Exception as e:
        log(f"GET /p/{t} -> ERR {e}")

# 4. /public/dashboard/{token} variants — try with random and with our tokens
import random, string
for t in short_tokens[:1]:
    for path in [f"/public/dashboard/{t}", f"/public/dashboards/{t}", f"/public/board/{t}", f"/public/{t}"]:
        try:
            r = sh.request("GET", BASE+path, headers={"User-Agent":"Mozilla/5.0"})
            log(f"GET {path} -> {r.status_code} ct={r.headers.get('Content-Type','')[:40]} body_first={r.text[:120]!r}")
        except Exception as e:
            log(f"GET {path} -> ERR {e}")
        time.sleep(0.5)

# Random 22-char b58 token (clean reject?)
rand22 = ''.join(random.choices(b58_alphabet, k=22))
for path in [f"/p/{rand22}", f"/public/dashboard/{rand22}"]:
    try:
        r = sh.request("GET", BASE+path, headers={"User-Agent":"Mozilla/5.0"})
        log(f"GET {path} (random) -> {r.status_code} body_first={r.text[:120]!r}")
    except Exception as e:
        log(f"GET {path} -> ERR {e}")
    time.sleep(0.5)

LOG.close()
