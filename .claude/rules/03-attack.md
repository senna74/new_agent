# ATTACK STRATEGY — STARTS ONLY AFTER RECON COMPLETE

## HARD GATE
IF targets/<TARGET>/recon/RECON-COMPLETE.md does NOT exist → STOP.

## INPUTS (mandatory, must exist)
targets/<TARGET>/recon/endpoints-complete.txt
targets/<TARGET>/recon/permission-map.json

## DISPATCH
For every endpoint in endpoints-complete.txt:
  Test ALL roles: ADMIN, MEMBER, IDOR, no-auth
  Compare actual access vs permission-map.json
  Gap = finding candidate → triage immediately

Special:
  billing_v2/*         → attack-idor + attack-privesc
  service-accounts     → attack-idor + attack-privesc
  audit-logs           → attack-privesc
  webhooks             → attack-ssrf
  scim                 → attack-auth + attack-idor
  upload endpoints     → attack-rce

## RULES
Use safe_http.py only — no inline requests
Use tools/ scripts — no inline HTTP code
On 403/429 ×3 → pm.rotate_ip()
