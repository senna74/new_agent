#!/usr/bin/env python3
"""
scope_gate.py — PreToolUse hook
Runs before every Bash call.
Blocks out-of-scope hosts + circuit breaker cooldown.
"""
import json, sys, os, re, time

def load_active_target():
    f = '/home/hunter/new_agent/state/.active-target'
    if not os.path.exists(f): return None
    return open(f).read().strip()

def load_scope(target):
    f = f'/home/hunter/new_agent/targets/{target}/scope.md'
    if not os.path.exists(f): return [], []
    content = open(f).read()
    in_scope, out_scope = [], []
    section = None
    for line in content.splitlines():
        if 'out_of_scope' in line: section = 'out'
        elif 'in_scope' in line: section = 'in'
        elif line.strip().startswith('-'):
            val = line.strip().lstrip('- ').strip()
            if section == 'in': in_scope.append(val)
            elif section == 'out': out_scope.append(val)
    return in_scope, out_scope

def extract_host(cmd):
    m = re.search(r'https?://([a-zA-Z0-9._-]+)', cmd)
    return m.group(1) if m else None

def check_circuit_breaker():
    f = '/tmp/new_agent_circuit_breaker.json'
    if not os.path.exists(f): return False
    try:
        data = json.load(open(f))
        if data.get('tripped') and time.time() - data.get('time', 0) < 60:
            return True
        elif data.get('tripped') and time.time() - data.get('time', 0) >= 60:
            json.dump({'tripped': False}, open(f, 'w'))
    except: pass
    return False

try:
    data = json.load(sys.stdin)
    tool = data.get('tool_name', '')
    cmd  = data.get('tool_input', {}).get('command', '')

    if check_circuit_breaker():
        print(json.dumps({"decision": "block", "reason": "circuit breaker — 60s cooldown active"}))
        sys.exit(0)

    target = load_active_target()
    if target:
        in_scope, out_scope = load_scope(target)
        host = extract_host(cmd)
        if host:
            for blocked in out_scope:
                blocked = blocked.lstrip('*.')
                if blocked and (host == blocked or host.endswith('.' + blocked)):
                    print(json.dumps({"decision": "block", "reason": f"out-of-scope: {host}"}))
                    sys.exit(0)

    print(json.dumps({"decision": "approve"}))

except Exception as e:
    print(json.dumps({"decision": "approve"}))
