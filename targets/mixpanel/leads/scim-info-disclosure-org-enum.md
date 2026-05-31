# LEAD — Organization ID enumeration oracle via Service Accounts endpoint

## Hypothesis
`GET /api/app/organizations/{org_id}/service-accounts` returns **403 "User does not have permission"** when `{org_id}` exists but caller is not a member, and **404 "Not Found"** when `{org_id}` does not exist. This 403-vs-404 split enables enumeration of valid Mixpanel organization IDs by any authenticated user.

## Evidence
| org_id tested | Caller | Response |
|---------------|--------|----------|
| 3100780 (likely real) | ADMIN of 3100781 | 403 |
| 3100782 | ADMIN of 3100781 | 403 |
| 3100790 | ADMIN of 3100781 | 403 |
| 3100791 | ADMIN of 3100781 | 403 |
| 3100795 (real — IDOR's org) | ADMIN of 3100781 | 403 |
| 3100800 | ADMIN of 3100781 | 403 |
| 1 (clearly real, oldest) | ADMIN of 3100781 | 403 |
| 100 (likely free slot) | ADMIN of 3100781 | **404** |
| 1000 | ADMIN of 3100781 | **404** |
| 999999999 (too large) | ADMIN of 3100781 | **404** |

## Impact (low, but submittable as info disclosure)
- Reveals which org IDs are allocated → useful for targeted phishing, sales-funnel intel, OSINT.
- Combined with the BFLA (separate finding) and any future cross-tenant bug, this provides the enumeration primitive an attacker needs to pick targets.

## Why this is a lead and not a finding
Severity is too low to submit standalone (CVSS ~3.7). Mixpanel may consider integer org IDs as non-sensitive. Promote only if a chain is found with cross-tenant access.

## Suggested chain candidates
- Combine with: org-invitation acceptance flaw, partner SSO bypass, or SCIM provisioning enumeration once the SCIM bearer-token bootstrap can be reached.
