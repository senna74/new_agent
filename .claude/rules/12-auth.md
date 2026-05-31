# AUTH + TOKEN MANAGEMENT

## TOKEN LOADING
import json
tokens = json.load(open('targets/<TARGET>/recon/tokens.json'))
admin_jwt    = tokens['ADMIN']['jwt']
member_jwt   = tokens['MEMBER']['jwt']
idor_jwt     = tokens['IDOR']['jwt']
admin_cookie = tokens['ADMIN']['full_cookies']

## TOKEN REFRESH
On 401:
  python3 ~/new_agent/.claude/lib/oidc-login.py <ROLE> [<START_URL>]
  Reload tokens.json
  Retry immediately — never stop

## CREDENTIAL FORMATS (scope.md accepts all)
username + password → auto-login via oidc-login.py
jwt: <token>        → use as Bearer token directly
cookie: <string>    → use as Cookie header directly
api_key: <key>      → use as X-API-Key or Authorization header

## SESSION HEALTH CHECK
Before each wave probe all accounts:
  GET /api/me or equivalent with each token
  200 → healthy
  401 → refresh immediately
  403 → log as role confusion finding candidate
