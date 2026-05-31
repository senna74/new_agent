---
name: api-security
description: "Use this skill whenever you see API endpoints — REST routes (/api/, /v1/, /v2/), GraphQL endpoints (/graphql, /query), WebSocket upgrades (wss://, ws://), Web-LLM endpoints (/chat, /completion), or Swagger/OpenAPI docs (/swagger, /openapi.json, /api-docs). Covers IDOR on API objects, GraphQL introspection abuse, REST verb tampering, WebSocket auth bypass, and Web-LLM attack techniques. Only invoke this skill if there is real impact potential. Skip theoretical findings."
---

# API Security

Test API endpoints for security vulnerabilities across REST, GraphQL, WebSocket, and LLM-integrated APIs.

## Techniques

| Type | Key Vectors |
|------|-------------|
| **GraphQL** | Introspection, batching attacks, nested query DoS, field suggestion |
| **REST API** | BOLA/IDOR, mass assignment, rate limiting, auth bypass, versioning |
| **WebSocket** | Cross-site hijacking, message manipulation, auth flaws |
| **Web-LLM** | Prompt injection via API, excessive agency, data exfiltration |

## Workflow

1. Discover API endpoints and documentation (Swagger, GraphQL schema)
2. Map authentication and authorization mechanisms
3. Test per API type using appropriate techniques
4. Validate data exposure and access control flaws
5. Capture evidence with HTTP request/response logs

## Reference

- `reference/graphql*.md` - GraphQL attack techniques and labs
- `reference/api-testing*.md` - REST API security testing guide
- `reference/websockets*.md` - WebSocket vulnerability testing
- `reference/web-llm*.md` - Web-LLM attack techniques and labs
- `reference/zabbix-jsonrpc-quickstart.md` - Zabbix JSON-RPC API: fingerprint, user.update privesc, selectRole SQLi, script.create+execute RCE

## Fallback Chain
1. Try the techniques in this skill first
2. If they fail or don't apply, use your own creativity
3. Never stop because a technique didn't work
4. Always find another angle
