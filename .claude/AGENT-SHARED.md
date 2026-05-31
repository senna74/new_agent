# AGENT SHARED BOOTSTRAP — read this first, every subagent, every time

## HTTP SETUP
import sys, os, json
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp
from proxy_manager import ProxyManager
sh = SafeHttp(allow_raw_for_waf=True)
pm = ProxyManager()
pm.ensure_running()

## TOKEN LOADING
TARGET = open('/home/hunter/new_agent/state/.active-target').read().strip()
tokens = json.load(open(f'/home/hunter/new_agent/targets/{TARGET}/recon/tokens.json'))
ADMIN  = tokens.get('ADMIN', {})
MEMBER = tokens.get('MEMBER', tokens.get('LOW', {}))
IDOR   = tokens.get('IDOR', {})

def auth_header(role_dict):
    if role_dict.get('jwt'):
        return {"Authorization": f"Bearer {role_dict['jwt']}"}
    if role_dict.get('full_cookies'):
        return {"Cookie": role_dict['full_cookies']}
    return {}

## QUEUE EMIT
import time
QUEUE = f'/home/hunter/new_agent/state/queue.jsonl'
def emit(event_type, **kwargs):
    entry = {"event": event_type, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ"), **kwargs}
    with open(QUEUE, 'a') as f:
        f.write(json.dumps(entry) + '\n')

## SESSION LOG
LOG = f'/home/hunter/new_agent/targets/{TARGET}/notes/session-log.md'
def log(msg):
    with open(LOG, 'a') as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")

## ON 401 — REFRESH TOKEN
def refresh(role):
    os.system(f"python3 /home/hunter/new_agent/.claude/lib/oidc-login.py {role}")
    global tokens
    tokens = json.load(open(f'/home/hunter/new_agent/targets/{TARGET}/recon/tokens.json'))

## ON 403/429 ×3 — ROTATE PROXY
waf_count = {}
def observe_response(host, status):
    if status in (403, 429):
        waf_count[host] = waf_count.get(host, 0) + 1
        if waf_count[host] >= 3:
            pm.rotate_ip()
            waf_count[host] = 0
            emit('circuit_rotated', host=host)
    else:
        waf_count[host] = 0
