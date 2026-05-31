---
name: hunt-race-condition
description: "Hunting skill for race condition vulnerabilities. Built from 3 public bug bounty reports. Use when hunting race condition on any target. Only invoke this skill if there is real impact potential. Skip theoretical findings."
sources: github
report_count: 3
---

## Crown Jewel Targets

Race conditions are high-severity findings because they break financial, access control, and integrity assumptions that defenders rarely stress-test. Highest payouts come from:

- **Monetary/credit systems** — double-spending gift cards, coupons, referral bonuses, promotional credits, wallet balances
- **Vote/reputation manipulation** — upvoting the same content multiple times, gaming leaderboards or trending algorithms
- **Account limits bypass** — exceeding free-tier quotas, bypassing "one per user" restrictions on invites, trial activations, or API key generation
- **Privilege escalation** — racing role assignment or permission checks during user creation/upgrade flows
- **Deletion bypass** — reading or exfiltrating data during a narrow window between "marked for deletion" and "actually deleted"
- **Payment flows** — charging a card once but receiving multiple fulfillments

**Best-paying asset types:** Fintech apps, SaaS platforms with credit/subscription models, social platforms with reputation systems, e-commerce checkout flows, OAuth/SSO token endpoints.

---

## Attack Surface Signals

### URL Patterns
```
/vote, /upvote, /like, /favorite
/redeem, /apply-coupon, /use-code, /claim
/purchase, /checkout, /confirm-order, /pay
/transfer, /withdraw, /send-money
/invite, /referral, /accept-invite
/upgrade, /activate, /trial
/delete, /deactivate, /cancel
/follow, /subscribe
```

### Response Headers That Signal Race-Prone Backends
```
X-RateLimit-*        # rate limiting exists, but may not be atomic
X-Request-Id         # each request independently tracked
No Cache-Control     # stateful ops not idempotent
```

### JavaScript Patterns to Grep
```javascript
// Single-use action buttons with client-side disable
button.disabled = true
$('#btn').prop('disabled', true)
// Optimistic UI updates (state set before server confirms)
setState({ used: true })
// Sequential async calls without locking
await useVoucher(); await deductBalance();
```

### Tech Stack Signals
- **Ruby on Rails** without `with_lock` / `lock!` — ActiveRecord doesn't lock by default
- **Node.js** with async/await chains — non-atomic DB reads then writes
- **PHP** without `SELECT ... FOR UPDATE` — common in legacy codebases
- **Microservices** — inter-service calls introduce natural TOCTOU windows
- **Redis counters** without Lua scripts or `INCR` atomicity checks
- **Message queues** — idempotency keys often missing

---

## Step-by-Step Hunting Methodology

1. **Enumerate one-time or limited-use actions** — Map every endpoint that enforces a "once per user", "limited quantity", or "deduct balance" constraint. These are your primary targets.

2. **Understand the state machine** — For each target action, identify: (a) what state is read, (b) what state is written, (c) what validation sits between read and write. The gap between read and write is your window.

3. **Capture a clean baseline request** — Perform the action once legitimately with Burp Suite intercepting. Confirm you get the expected single-use behavior (e.g., coupon marked used, vote counted once).

4. **Set up parallel request tooling** — Use one of:
   - Burp Suite Repeater → "Send group in parallel" (Turbo Intruder for HTTP/2 single-packet attacks)
   - Turbo Intruder with `engine=Engine.BURP2` for last-byte sync
   - `curl` with `&` backgrounding
   - Python `threading` or `asyncio` with pre-built connections

5. **Execute the race** — Send 10–50 identical requests simultaneously. Key technique: **pre-connect and buffer all requests, release the final byte of all simultaneously** (single-packet attack when HTTP/2 is available).

6. **Analyze responses** — Look for:
   - Multiple `200 OK` where only one should succeed
   - Duplicate success messages
   - Database constraint errors (signals the race worked but hit the last-line-of-defense)
   - Inconsistent response times (one fast, rest slow = serialized; all same speed = parallel processing)

7. **Verify the effect** — Check the actual state: Was the credit applied twice? Did the vote count increment multiple times? Is the coupon still marked unused despite two successes?

8. **Determine exploitability window** — Re-run with decreasing parallelism (5 requests, 3 requests, 2 requests) to understand how tight the window is and reliability of exploitation.

9. **Test across account types** — Sometimes the race only works for new accounts, specific subscription tiers, or under specific server load. Test varied conditions.

10. **Document reproducibility** — Record exact timing, number of parallel requests needed, and success rate across 5 independent attempts before reporting.

---

## Payload & Detection Patterns

### Turbo Intruder — Basic Parallel Race
```python
# turbo_intruder_race.py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)  # HTTP/2 single-packet
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    if '200' in req.status:
        table.add(req)
```

### curl — Parallel Requests (bash)
```bash
# Fire 15 simultaneous vote/redeem requests
for i in $(seq 1 15); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST "https://target.com/api/vote" \
    -H "Cookie: session=YOUR_SESSION" \
    -H "Content-Type: application/json" \
    -d '{"report_id": "12345", "vote": "up"}' &
done
wait
```

### Python asyncio Race
```python
import asyncio, aiohttp

async def race_request(session, url, payload, headers):
    async with session.post(url, json=payload, headers=headers) as r:
        return await r.text()

async def main():
    url = "https://target.com/redeem"
    payload = {"code": "GIFT50"}
    headers = {"Cookie": "session=XXXXX"}
    
    async with aiohttp.ClientSession() as session:
        tasks = [race_request(session, url, payload, headers) for _ in range(20)]
        results = await asyncio.gather(*tasks)
    
    for r in results:
        print(r[:100])  # print first 100 chars of each response

asyncio.run(main())
```

### Grep Patterns for Source Code Auditing
```bash
# Look for read-then-write without locking
grep -rn "find_by\|where.*first" --include="*.rb" | grep -v "lock"
grep -rn "SELECT.*WHERE" --include="*.php" | grep -v "FOR UPDATE"

# JavaScript async without atomicity
grep -rn "await.*get\|await.*find" --include="*.js" -A2 | grep "await.*update\|await.*save"

# Python Django ORM without select_for_update
grep -rn "\.get(\|\.filter(" --include="*.py" | grep -v "select_for_update"
```

### HTTP/2 Single-Packet Check
```bash
# Verify target supports HTTP/2 (prerequisite for single-packet attack)
curl -sI --http2 https://target.com | grep -i "HTTP/2\|h2"
```

---

## Common Root Causes

1. **Check-Then-Act without atomic operations** — Developer reads state (`if voucher.used == false`), then writes state (`voucher.update(used: true)`) in two separate database operations. Any thread can read the same "unused" state before either writes.

2. **Missing database-level locking** — Using ORM methods like `find` or `filter` instead of `SELECT ... FOR UPDATE`. The fix is one line but developers don't think about concurrency.

3. **Optimistic concurrency without version checking** — Systems increment counters or mark records without checking if the record changed since it was read.

4. **Microservice TOCTOU** — Service A validates eligibility, Service B executes the action. No shared atomic transaction spans both services.

5. **Client-side "protection"** — Developers disable the button in JavaScript after first click, assuming that prevents duplicate submissions. Server-side logic is never hardened.

6. **Counter increments outside transactions** — `votes_count += 1; save()` instead of an atomic SQL `UPDATE SET votes = votes + 1 WHERE id = ?`.

7. **Async background jobs** — Eligibility checked synchronously, fulfillment done asynchronously. A second request passes the check before the first job completes.

8. **Caching without invalidation** — Cached "has user voted?" check returns stale `false` during a cache miss window when the first write hasn't propagated yet.

---

## Bypass Techniques

### What Defenders Implement (and How to Bypass)

**Defense: Per-user rate limiting**
- Bypass: Rate limits are checked before the action executes. Send requests simultaneously — all pass the rate-limit check before any is counted.

**Defense: Idempotency keys / unique request tokens**
- Bypass: If the server generates or reuses the token, try sending parallel requests without the token. Or check if the uniqueness check itself has a race window.

**Defense: Database unique constraints**
- Bypass: The constraint catches duplicates *after* the race. The first two may both succeed before DB enforces. Look for partial fulfillment — sometimes one succeeds and one errors but both are honored.

**Defense: Short time windows / expiring tokens**
- Bypass: Pre-stage all requests with valid tokens. Use single-packet HTTP/2 to release all in one TCP frame — server processes them in the same scheduler slot.

**Defense: Queue-based serialization**
- Bypass: Multiple queues (or multiple workers consuming the same queue) can pick up duplicate messages. Test by overwhelming the queue during the window.

**Defense: Application-layer mutex / locks**
- Bypass: Distributed systems running multiple app servers don't share in-process locks. Send requests to the same endpoint via different CDN nodes or load-balanced servers.

**Defense: "Already used" checks in application code**
- Bypass: The check and the update are separate. The check passes for both racing requests before either update completes. Only an atomic `UPDATE ... WHERE used=false RETURNING id` truly prevents this.

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   Can you demonstrate — with screenshots or logs — that the same one-time action succeeded more than once? (e.g., vote count shows +2 from one user, credit balance shows double-credit, coupon shows redeemed twice)

2. **What does the victim LOSE?**
   Is there concrete, measurable harm? Financial loss (credits issued in excess), integrity loss (manipulated rankings/votes), or security loss (access granted beyond entitlement)? "The counter went up twice" is only valid if that counter has real-world value.

3. **Can it be reproduced in 10 minutes from scratch?**
   Can you write a 20-line script, run it against a fresh test account, and reliably demonstrate the duplicate effect at least 3/5 attempts? If it requires perfect timing you cannot reliably control, the exploitability claim is weak.

---

## Real Impact Examples

### Scenario 1: Social Platform Vote Manipulation
A bug bounty platform's "popular reports" feature allowed upvotes to improve report visibility and researcher reputation scores. By sending ~15 parallel upvote requests for the same report using a single HTTP/2 connection (single-packet attack), a researcher was able to register 10–15 votes from a single account. This allowed artificial inflation of report rankings, manipulation of researcher reputation scores, and distortion of the platform's crowdsourced prioritization system — directly undermining trust in the platform's core feature for triaging vulnerability reports.

### Scenario 2: Major Social Network — Duplicate Promotional Actions
On a major social network (Facebook-scale), promotional or limited-use actions — such as adding a phone number for a one-time security credit, or claiming a one-time bonus — were vulnerable to simultaneous parallel requests. An attacker could race the claim endpoint and receive the promotional benefit multiple times, causing direct financial loss to the platform and allowing fraudulent accumulation of platform currency or benefits at scale. Given the user volume, even a brief window before patching represented significant financial exposure.

### Scenario 3: Cloud Infrastructure Provider — Resource Limit Bypass
A cloud hosting provider enforced limits on the number of resources (e.g., droplets, projects, or API keys) a free-tier user could create. The limit check and resource creation were non-atomic operations. By racing the creation endpoint with 20 simultaneous requests, an attacker bypassed the enforcement logic and created resources far exceeding their tier limit. This translated directly to unauthorized compute consumption, billing fraud, and abuse of infrastructure — impacting both the provider's revenue and system stability for legitimate users.

---

## Microservices-Specific Race Conditions (2026 Edition)

Service-decomposed architectures multiply race windows: every service-to-service hop is a TOCTOU opportunity, and per-service rate limits don't compose into a global one. Defenders test each service in isolation; the race lives in the gap.

### 1. Double-Spend Across Service Boundaries

The most lucrative microservices race. The payment-service and wallet-service are separate. The "spend" endpoint:
```
[client] → POST /api/spend
[orders-svc] → check wallet-svc: GET /wallets/X/balance → 100
[orders-svc] → fulfill order (mark inventory, generate receipt)
[orders-svc] → debit wallet-svc: POST /wallets/X/debit (100)
```
Race two `/api/spend` calls in parallel. Both hit the balance check at "100." Both fulfill. Both then debit — and the wallet either goes negative (free goods) or one debit fails (free goods anyway, order already fulfilled).

**Telltale signals of cross-service balance checks:**
- Order placement returns instantly but balance debit appears in account history seconds later
- Order success even though balance "should" have failed concurrently
- Multiple debits with same `idempotency_key` but no rejection (idempotency check is local to debit service, not cross-service)

**Probe:**
```python
# Single-packet attack against /api/spend twice with balance at exactly cost
import threading, requests
def fire(): requests.post(URL, json={"item":"X","price":100}, headers=H)
threads = [threading.Thread(target=fire) for _ in range(5)]
for t in threads: t.start()
for t in threads: t.join()
# Then GET /wallet: balance < 0 OR multiple order IDs both fulfilled
```

### 2. Coupon / Promo Code Abuse

Coupon-service and order-service decoupled. Coupon-service marks code "used" after order-service confirms. Window: order confirmation hasn't propagated when second request arrives.

**Vectors:**
- One-time discount codes (10%/50%/free trial)
- Welcome bonuses tied to first order
- Referral credits granted on signup
- Free-trial activation tied to "no prior subscription"
- "First purchase" loyalty multipliers

**Pattern:** apply coupon to 5 simultaneous orders. All succeed because coupon-service only marks "used" after order completion confirmation lands.

**Higher-value variant:** apply *different* one-per-user coupons in parallel, hitting eligibility check ("user has no active coupon") simultaneously, ending up with N stacked discounts.

### 3. Paywall / Subscription Tier Bypass

```
[paywall-svc] checks subscription → "free tier, blocked"
[content-svc] serves content based on header from paywall-svc
```
Race two requests to the same metered endpoint while you're at "0 articles read this month":
- Both pass the metering check (count=0)
- Both increment the counter
- Counter ends at 2, but both responses delivered

Scale this against an article-per-month metered news site → unlimited reads at scale. Worse on per-API-call billing — race ~100 requests, get billed for 1.

### 4. Parallel Payment Processing (Double Capture)

Stripe/Braintree/Adyen integrations create a payment-intent on the gateway, then the app's payment-service captures it. If "capture" is racey:
```
[gateway] payment_intent_id=PI_abc, amount=100
[order-svc] capture(PI_abc) → already captured (idempotent)
                              → but order-svc creates a *second* order locally
                              → both orders fulfilled, customer charged once
```
Or the inverse (more dangerous for the merchant): the app captures + fulfills before the gateway returns, sends a duplicate capture, gets it failed, but doesn't roll back the fulfillment.

**Detection:** order history shows 2 receipts with the same `payment_intent_id` or same Stripe charge ID. If reconciliation only happens daily, you ship twice before it's caught.

### 5. Inventory Decrement vs Order Creation

Classic e-commerce race: stock-svc has 1 unit. Two buyers race the checkout. Both pass stock-svc's `stock > 0` check before either decrement lands. Both orders confirm. One ships, the other gets a manual refund, but goodwill credits / free shipping often persist.

**Higher-impact variant:** for digital-only goods (license keys, gift cards), inventory race creates *duplicate code issuance* — same key sold to N buyers, each can redeem.

### 6. Webhook Idempotency vs Side-Effect Race

Stripe/PayPal/GitHub webhooks have signature + idempotency key. Many apps:
- Check signature
- Look up idempotency key (NOT found, first time)
- Process the event (issue refund, grant license)
- Insert idempotency key

Race two identical webhook deliveries (replay attack with Stripe CLI or signed event replay): both see "not yet processed," both grant the side effect, idempotency key written twice but side effect happened twice.

### 7. Saga / Distributed Transaction Compensation Race

In saga patterns, if step 3 fails, the system fires compensating actions for steps 1 and 2. Race the compensation: trigger the failure case, then before the rollback hits, perform another action that depends on step 1's success.

Concrete: "Transfer money" saga: debit A, credit B, audit log. Force the credit-B step to fail (e.g., recipient suspended via your other session). Compensation reverses the debit. But if you race a *second* debit through during the compensation window, you withdraw twice but only owe once.

### Probe Templates for Microservices Races

```python
# Cross-service double-spend probe
import asyncio, aiohttp
async def spend(s, amt):
    return await (await s.post("https://target.com/api/spend",
                                json={"item":"x","price":amt})).json()
async def main():
    async with aiohttp.ClientSession(cookies={"sess":"YOUR"}) as s:
        # Set balance to exactly 100 first, then:
        results = await asyncio.gather(*[spend(s, 100) for _ in range(5)])
        for r in results: print(r)
        # Then check balance — if < 0 or multiple order IDs, race confirmed
asyncio.run(main())
```

```bash
# Stripe-style webhook replay race (with valid signature)
SIG="t=...,v1=..."
for i in $(seq 1 5); do
  curl -X POST https://target.com/webhooks/stripe \
    -H "Stripe-Signature: $SIG" \
    -d @event.json &
done
wait
# Check if refund/license-grant happened multiple times
```

### Microservices Race Defenses (and how they fail)

**Defense: per-service idempotency keys**
- Failure mode: idempotency keys are per-service; the *side effect* may happen across services that don't share the key. Wallet-svc has idempotency but order-svc doesn't — race the order fulfillment.

**Defense: distributed locks (Redis Redlock, Zookeeper)**
- Failure mode: lock granularity is wrong (locking the user, not the resource). Or lock TTL is shorter than the operation, so two ops both hold "valid" locks.

**Defense: optimistic concurrency control (version columns)**
- Failure mode: only enforced on one service's DB. Cross-service operations skip it.

**Defense: 2-phase commit / saga**
- Failure mode: compensating actions are not atomic with the main action — see #7 above.

**Defense: event sourcing with single writer**
- Failure mode: only sees its own events. Reads come from projections that lag — race against the projection lag.

### Chain Primitive

**Cross-service race + idempotency-key-not-shared + payment-svc → double charge for single product** — pays critical in fintech.

**Race + coupon promo with welcome bonus + referral system → unlimited credit generation** — direct fraud, pays high.

**Race + saga compensation + audit-log lag → undetected money movement** — chain into reputation/compliance angle for max payout.

---

## Related Skills & Chains

- **`hunt-business-logic`** — Race conditions are the "concurrency arm" of every business-logic state machine. Chain primitive: business logic (coupon/promo) + race-condition single-packet attack → coupon redeemed N times → direct financial loss.
- **`hunt-mfa-bypass`** — OTP-expiry windows and replay protection are classic race targets. Chain primitive: race + MFA-validate endpoint → bypass OTP expiry by submitting N concurrent validations within the validity window.
- **`hunt-ato`** — Race conditions on password reset, email change, and account creation enable persistent ATO. Chain primitive: race on email-change endpoint + atomic-update missing → swap victim email + read reset token before user notice.
- **`hunt-api-misconfig`** — Wallet/balance/credit endpoints without atomic UPDATE are double-spend candidates. Chain primitive: race + atomic-update missing → double-spend balance → withdraw N× user balance.
- **`security-arsenal`** — Load the Turbo Intruder single-packet template, h2.cl smuggling for atomic submit, and `curl --next` parallel multi-request patterns.
- **`triage-validation`** — Apply the Statistical-Sampling gate: a single anomalous response is noise; require 1 successful + N duplicate / over-quota / stale-state demonstrations with response screenshots before reporting.

## Fallback Chain
1. Try the techniques in this skill first
2. If they fail or don't apply, use your own creativity
3. Never stop because a technique didn't work
4. Always find another angle

## Real-World Reports (from Community Writeups)

Pulled from HackerOne TOPRACECONDITION. Techniques in 3+ reports are **PROVEN**.

| Title (truncated) | Program | Bounty | Source |
|---|---|---|---|
| **Race Condition redeem gift cards multiple times** | Reverb.com | — | H1 #759247 |
| Race condition in performing retest → duplicated payments | HackerOne | — | H1 #429026 |
| Client-side race condition → data-protocol in Safari | HackerOne | — | H1 #381356 |
| Race Condition → undeletable group member | HackerOne | — | H1 #604534 |
| Race condition in activating email → infinite diamonds | InnoGames | $2,000 | H1 #509629 |
| **Bypassing HackerOne 2FA due to race condition** | HackerOne | — | H1 #2598548 |
| Race Conditions in Popular reports feature | HackerOne | — | H1 #146845 |
| Race Condition when following a user | every.org | — | H1 #927384 |
| Race exploiting loyalty claim → unlimited cash | Vend VDP | — | H1 #331940 |
| Race Condition Enables Bypassing Verification Check | Tools for Humanity | $3,000 | H1 #2110030 |
| Race Condition in Flag Submission | HackerOne | — | H1 #454949 |
| Race condition on add 1 free domain | Automattic | — | H1 #2616045 |
| Race Condition transfer Data Credits → extra free credits | Helium | $250 | H1 #974892 |
| Race condition leads to duplicate payouts | HackerOne | — | H1 #220445 |
| Race in joining CTF group | HackerOne | $500 | H1 #1540969 |
| Exceed max subscribers limit | SingleStore | — | H1 #3221185 |
| Email Verification Bypass via Race Condition | Malwarebytes | — | H1 #3020733 |
| Race condition in faucet using starport | Cosmos | $5,000 | H1 #1438052 |
| Race Condition coupon redeem multiple times | Instacart | — | H1 #157996 |
| Race condition GitLab import → access others' imports | GitLab | — | H1 #214028 |

**PROVEN technique signals (≥3 reports each):**
- **Coupon/gift-card/credit redeem** race (Reverb, Instacart, InnoGames, Dropbox, Helium, Weblate) — same code redeemed N times in parallel.
- **Invitation / membership limit bypass** (Keybase, Krisp, Omise, FetLife, Shopify) — exceed seat/member caps with parallel POST.
- **2FA / OTP / verification bypass race** (HackerOne, Malwarebytes, Tools for Humanity, Evernote) — multiple OTP-verify requests land before lockout/state-change.

## High-Value Chains (from Reports)

1. **Gift-card redeem race → financial loss (Critical)**
   - Example: Reverb.com H1 #759247 — same gift-card code redeemed in 30 parallel requests → 30x credit. Direct $$$.

2. **2FA verification race → MFA bypass → ATO**
   - Example: HackerOne H1 #2598548 — race on 2FA verify endpoint accepts more guesses than the lockout permits → brute force 6-digit code.

3. **Coupon-claim race → bypass per-user limit → mass financial drain**
   - Example: Instacart H1 #157996. Multiple parallel claims of one-time coupon.

4. **Email-verification race → unverified account gets verified perms**
   - Example: Malwarebytes H1 #3020733 — race between verify-token consumption and account-state update lets attacker bypass email verification.

5. **Resource-limit race (seats / domains / API keys) → cap bypass → resource exhaustion / financial**
   - Example: Cosmos H1 #1438052 ($5K) — race on faucet endpoint dispensed multiple tokens per request window.
