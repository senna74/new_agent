# RATE LIMITING + CIRCUIT BREAKER

## LIMITS (from pacer.py)
Default rate: 2.0 req/sec per domain (DEFAULT_RPS)
State file:   targets/<TARGET>/recon/.rate-state.json
Locking:      fcntl.LOCK_EX — cross-process safe

## CIRCUIT BREAKER (from waf_counter.py)
3 consecutive 403 or 429 from same host:
  Trip circuit breaker
  Emit {"event":"circuit_tripped","host":"<host>"} to queue.jsonl
  Wait 60s
  Call pm.rotate_ip() — new Tor circuit
  Resume

## WAF DETECTED
Route through Tor: socks5h://127.0.0.1:9050
Use pm.get_proxy_url() from proxy_manager.py
Add 1-3s random delay between requests
Rotate User-Agent per request

## PROXY ROTATION
pm = ProxyManager()
pm.ensure_running()
pm.rotate_ip()          # NEWNYM, 10s cooldown enforced
pm.current_exit_ip()    # verify new IP
pm.is_banned(host)      # heuristic check
Max 5 rotations → flag to notes/problems.md
