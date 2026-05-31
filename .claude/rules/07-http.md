# HTTP — safe_http.py ONLY

## MANDATORY PATTERN
import sys
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp
sh = SafeHttp(allow_raw_for_waf=True)
resp = sh.request("GET", url, headers={"Authorization": f"Bearer {token}"})

## WITH PROXY (WAF-protected targets)
from proxy_manager import ProxyManager
pm = ProxyManager()
pm.ensure_running()
proxies = {"http": pm.get_proxy_url(), "https": pm.get_proxy_url()}
resp = sh.request("GET", url, headers={...}, proxies=proxies)

## ON BAN
pm.rotate_ip()   # NEWNYM — 10s cooldown enforced internally

## NEVER
- Never use requests.get/post directly
- Never raw subprocess curl without safe_http
- Never print full response — truncate to 150 chars
- Never exceed DEFAULT_RPS = 2.0 per domain (pacer.py enforces)
