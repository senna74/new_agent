---
name: client-side
description: "Use this skill whenever you find reflected/stored user input in HTML responses, JavaScript sinks (innerHTML, document.write, eval), postMessage handlers, CORS-relevant cross-origin requests, iframe-able pages, or JSON-merge/Object.assign in client code. Covers XSS (reflected/stored/DOM), CSRF on state-changing actions, CORS misconfiguration with credentials, clickjacking on sensitive pages, DOM-based attacks, and prototype pollution. Only invoke this skill if there is real impact potential. Skip theoretical findings."
---

# Client-Side

Test for client-side vulnerabilities across modern web applications and SPAs.

## Techniques

| Type | Key Vectors |
|------|-------------|
| **XSS** | Reflected, Stored, DOM-based, framework-specific (React, Vue, Angular) |
| **CSRF** | Token bypass, SameSite cookie bypass, cross-origin requests |
| **CORS** | Misconfigured origins, null origin, wildcard credentials |
| **Clickjacking** | Frame-based, drag-and-drop, multi-step |
| **DOM-based** | DOM sinks, source/sink analysis, JavaScript URL schemes |
| **Prototype Pollution** | Client-side gadgets, server-side pollution, property injection |

## Workflow

1. Identify input sources and data flows
2. Classify sink contexts (HTML, attribute, URL, JS, CSS)
3. Enumerate defenses (encoding, CSP, sanitizers, Trusted Types)
4. Craft context-appropriate payloads
5. Validate execution and demonstrate impact
6. Document with reproduction steps and remediation

## Reference

- `reference/xss*.md` - XSS bypass techniques and exploitation
- `reference/csrf*.md` - CSRF techniques and bypasses
- `reference/cors*.md` - CORS misconfiguration testing
- `reference/clickjacking*.md` - Clickjacking techniques
- `reference/dom*.md` - DOM-based vulnerability testing
- `reference/prototype-pollution*.md` - Prototype pollution techniques

## Fallback Chain
1. Try the techniques in this skill first
2. If they fail or don't apply, use your own creativity
3. Never stop because a technique didn't work
4. Always find another angle
