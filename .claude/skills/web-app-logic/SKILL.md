---
name: web-app-logic
description: "Use this skill whenever you find multi-step workflows (checkout, refund, subscription change, role assignment), race-prone endpoints (token redemption, withdrawals, vote counting), access-control gates that can be bypassed by changing order/params/timing, or cache-served sensitive responses. Covers business-logic flaws, race conditions, access-control bypass, cache poisoning/deception, information disclosure. Only invoke this skill if there is real impact potential. Skip theoretical findings."
---

# Web Application Logic

Test for logic flaws and application-specific vulnerabilities that automated scanners miss.

## Techniques

| Type | Key Vectors |
|------|-------------|
| **Business Logic** | Workflow bypass, price manipulation, feature abuse |
| **Race Conditions** | TOCTOU, limit bypass, double-spend, parallel requests |
| **Access Control** | IDOR, horizontal/vertical privilege escalation, forced browsing |
| **Cache Poisoning** | Unkeyed headers/parameters, fat GET, response splitting |
| **Cache Deception** | Path confusion, static extension tricks, normalization |
| **Info Disclosure** | Error messages, debug endpoints, source code, metadata |

## Workflow

1. Map application workflows and business rules
2. Identify state-dependent operations and trust boundaries
3. Test logic assumptions with edge cases and race conditions
4. Verify access control across user roles
5. Document impact with PoC demonstrations

## Reference

- `reference/business-logic*.md` - Business logic testing techniques
- `reference/race-conditions*.md` - Race condition exploitation
- `reference/access-control*.md` - Access control bypass methods
- `reference/web-cache-poisoning*.md` - Cache poisoning techniques
- `reference/web-cache-deception*.md` - Cache deception attacks
- `reference/information-disclosure*.md` - Information disclosure testing

## Fallback Chain
1. Try the techniques in this skill first
2. If they fail or don't apply, use your own creativity
3. Never stop because a technique didn't work
4. Always find another angle
