# LEAD — Public-Board Share Link Mechanism (mixpanel.com)

**Status:** NEGATIVE result — no submittable finding
**Confidence:** 0.10 (no defect identified)
**Date:** 2026-05-30
**Scope:** mixpanel.com — project 4025923, dashboard 11207838 (ADMIN's "Starter Board")

## Summary
Comprehensive review of Mixpanel's public-board / share-link surface against the five threat hypotheses
(token predictability, metadata leak, persistence-after-disable, route confusion to non-public boards,
auth privilege confusion). The mechanism appears structurally sound; no exploitable issue was identified.

## Discovered share-management API
- Collection: `GET /api/app/projects/{PROJ}/public-dashboards` -> `200 {"results": []}` for ADMIN/MEMBER; cross-tenant (IDOR) gets the marketing "Request Access" page (correct enforcement).
- Resource: `OPTIONS /api/app/projects/{PROJ}/public-dashboards/{DASH}` -> `Allow: GET, POST, DELETE, HEAD, OPTIONS`.
- Create: `POST /api/app/projects/{PROJ}/public-dashboards/{DASH}` currently returns generic `500 Error ID: <hex>` because the project has `has_public_dashboards_enabled=false` (the feature is disabled by default per Mixpanel docs).
- We could not flip the project-level setting via any of the candidate API paths (`/projects/{PROJ}`, `/projects/{PROJ}/settings`, `/organizations/{ORG}/settings`, `/projects/{PROJ}/public-dashboard[-_]settings`, `/projects/{PROJ}/public_dashboard_settings`, etc — all 404). The toggle is only reachable through the authenticated SPA, which in this environment is gated by browser fingerprinting we cannot replicate from `requests`.
- Header-injection attempts to bypass the feature gate (`X-Original-URL`, `X-Forwarded-For`, `X-Real-IP`, `X-Internal`, `X-Mixpanel-Feature`, `X-MP-Feature-Flag`) all return the same generic 500.

## Token structure (recon-collected /p/<token> shorts)
| Token | b58-decoded hex | bytes |
|-------|----------------|-------|
| 2cv24kB3k5n9reXr9bSJKU | 0d1cd826218041e3bc4b21ba928daedb | 16 |
| 5dbqyToAtFMaDJVJNzUeuG | 2580cdd0ba31464b951bc97fabe42033 | 16 |
| BkaDwovdEpEcMJp33R6sah | 5710d7ddc70f454fbfcb440e7d42f732 | 16 |
| CEngFwLvPa5zvTSLvFTHNH | 5b0157f839384fc0ab349f2cabc29d62 | 16 |
| MKDgQSoYBZciN4AGgY7Mgh | a481f99a139f477984606c3761eaea4e | 16 |
| QLBHa24vdYuK2MJLiNUA1S | bcefa8da788741df964a7c80d6a8b0c5 | 16 |

All six decode to **16 fully-random bytes** via the standard Bitcoin base58 alphabet. No structural correlation
(no shared prefix, no embedded project_id, no monotonic counter, no timestamp). 128-bit entropy ≈ 3.4×10^38 keyspace
makes enumeration infeasible (at 100 req/s it would take >10^28 years to cover 1% of the space). The same byte
sequences also decode cleanly under url-safe base64 (also 16 bytes) — the chosen encoding is unambiguous.

## Endpoint behaviour
- `/p/<22-char-token>` -> `200` SPA shell HTML (byte-identical across all valid tokens; per-board data is fetched
  via a JS-driven XHR which we cannot trigger headlessly).
- `/public/<22-char-token>` -> identical shell as `/p/<token>`.
- `/public/dashboard/<token>` (path from task brief) -> `404`. This path does NOT exist on the current deployment.
- `/p/<random-22-char>` -> clean `404 KEEP IN SYNC w/ iron/common/widgets/404-screen`. **No oracle** (response shape is identical
  for non-existent and revoked tokens; no timing skew observed within ±0.4s noise).
- Auth attached vs no-auth: byte-identical response (SHA-256 of `/p/<valid>` body is identical across
  `no cookie` / `ADMIN cookie` / `MEMBER cookie` / `IDOR cookie`). **No privilege confusion / data leak from auth attachment.**

## Persistence-after-disable (#3)
**Not testable** in this environment — feature is disabled, no live link to disable. Cannot confirm or deny.

## Cross-tenant / route-confusion (#4)
- `/p/<token>` is a separate routing namespace from `/api/app/projects/{PROJ}/dashboards/{DASH}` — direct GET on the
  authenticated endpoint with a different role enforces project membership (IDOR session is redirected to the marketing
  "Request Access" page; only MEMBER and ADMIN of project 4025923 receive the dashboard JSON).
- The recon-collected `/p/<token>` shorts return 200 unauthenticated, which is the **intended behaviour for the public-board
  feature** (these belong to other Mixpanel customers who explicitly opted-in to public sharing). Confirmed they ARE public
  boards (the iframely meta tag and noindex robots directive are present); per task constraints we did not query the data XHRs
  of those boards.

## oEmbed / cross-tenant embed abuse (#6)
`/oembed`, `/api/oembed`, `/api/app/oembed`, `/api/app/embeds`, `/oembed.json` all return `404`. **No oEmbed surface present.**

## Why not a finding
1. No predictable token (128-bit cryptographic randomness, base58-encoded).
2. No oracle on 404 (clean reject, no timing/length signal).
3. No metadata leak from the unauthenticated shell page (identical bytes across boards).
4. No auth-confusion (cookies don't change response).
5. No oEmbed.
6. Project-API endpoints correctly enforce membership.
7. POST 500 is consistent across all roles — not a privilege issue, just feature-disabled.

## What was NOT possible to test in this environment
- Creating a public link end-to-end (requires SPA-only feature-enable toggle).
- Persistence-after-disable (no live link to disable).
- Per-board metadata leakage in the public-viewer XHR (the SPA fetches it via JS we cannot execute headlessly).

For full coverage these gaps would require Playwright with an authenticated browser session and the project's
"Public Boards" feature toggled on in Project Settings → Permissions.

## Evidence
- `/home/hunter/new_agent/results/mixpanel/probe_share*.py` — all 15 probe scripts
- `/home/hunter/new_agent/results/mixpanel/probe_share*_log.txt` — raw HTTP traces
- `/home/hunter/new_agent/results/mixpanel/p_2cv24kB3k5n9reXr9bSJKU.html` — captured public-board shell
- `/home/hunter/new_agent/results/mixpanel/board__api_app_projects_4025923_dashboards_11207838.json` — admin dashboard view
- `/home/hunter/new_agent/results/mixpanel/list__api_app_projects_4025923_dashboards_.json` — dashboards list

## Cleanup
No public dashboards were ever created (POST always 500'd). No board state was modified. No data was exfiltrated from
other tenants' `/p/<token>` pages (only the SPA shell was fetched, which contains no per-board content).
