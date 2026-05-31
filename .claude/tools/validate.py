#!/usr/bin/env python3
"""
validate.py — deterministic finding validator
Usage: validate.py <finding.json>

Input JSON schema (one finding):
{
  "method": "GET|POST|...",
  "url": "https://...",
  "headers": {"k": "v"},
  "body": "string-or-omitted",
  "expected": {
      "status": 200,                          # required match
      "body_contains": ["string1","string2"], # all must appear
      "body_not_contains": ["err"],           # none may appear
      "header_match": {"X-Foo":"bar"}         # case-insensitive
  }
}

Output: JSON
  {"status":"CONFIRMED|FALSE_POSITIVE|NEEDS_MANUAL","reason":"...","observed":{...}}

Pure HTTP. No LLM. No interpretation. Two replays — same outcome both times = CONFIRMED.
"""
import json
import sys
import urllib.request
import urllib.error
import ssl

UA = "Mozilla/5.0 (compatible; validator/1.0)"
TIMEOUT = 15
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def fetch(method, url, headers, body):
    data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method.upper())
    req.add_header("User-Agent", UA)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx)
        body_bytes = resp.read(65536)
        return {"status": resp.status, "headers": dict(resp.headers), "body": body_bytes.decode("utf-8", errors="replace")}
    except urllib.error.HTTPError as e:
        body_bytes = e.read(65536) if e.fp else b""
        return {"status": e.code, "headers": dict(e.headers or {}), "body": body_bytes.decode("utf-8", errors="replace")}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def check(obs, expected):
    if "error" in obs:
        return ("NEEDS_MANUAL", obs["error"])
    exp_status = expected.get("status")
    if exp_status is not None and obs["status"] != exp_status:
        return ("FALSE_POSITIVE", f"status {obs['status']} != expected {exp_status}")
    body = obs.get("body", "")
    for needle in expected.get("body_contains", []):
        if needle not in body:
            return ("FALSE_POSITIVE", f"body missing required substring: {needle!r}")
    for needle in expected.get("body_not_contains", []):
        if needle in body:
            return ("FALSE_POSITIVE", f"body contains forbidden substring: {needle!r}")
    hdr_lower = {k.lower(): v for k, v in obs.get("headers", {}).items()}
    for k, v in expected.get("header_match", {}).items():
        if hdr_lower.get(k.lower()) != v:
            return ("FALSE_POSITIVE", f"header {k}={hdr_lower.get(k.lower())!r} != expected {v!r}")
    return ("CONFIRMED", "all expectations satisfied")


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"status": "NEEDS_MANUAL", "reason": "usage: validate.py <finding.json>"}))
        sys.exit(2)
    with open(sys.argv[1]) as f:
        finding = json.load(f)

    method = finding.get("method", "GET")
    url = finding["url"]
    headers = finding.get("headers", {})
    body = finding.get("body")
    expected = finding.get("expected", {})

    obs1 = fetch(method, url, headers, body)
    verdict1, reason1 = check(obs1, expected)

    obs2 = fetch(method, url, headers, body)
    verdict2, reason2 = check(obs2, expected)

    if verdict1 == verdict2 == "CONFIRMED":
        out = {"status": "CONFIRMED", "reason": "verified across two replays", "observed_status": obs1["status"]}
    elif verdict1 != verdict2:
        out = {"status": "NEEDS_MANUAL", "reason": f"non-deterministic: replay1={verdict1}/{reason1}, replay2={verdict2}/{reason2}"}
    else:
        out = {"status": verdict1, "reason": reason1, "observed_status": obs1.get("status")}

    print(json.dumps(out))


if __name__ == "__main__":
    main()
