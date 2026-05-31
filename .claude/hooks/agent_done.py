#!/usr/bin/env python3
"""
agent_done.py — SubagentStop hook
Clears agent lock when subagent finishes.
Logs cost.
"""
import json, sys, os, time

LOCK      = '/tmp/new_agent_agent_running.lock'
COST_FILE = '/tmp/new_agent_costs.json'

try:
    data = json.load(sys.stdin)
    if os.path.exists(LOCK):
        os.remove(LOCK)
    costs = json.load(open(COST_FILE)) if os.path.exists(COST_FILE) else []
    costs.append({
        "ts":         time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent":      data.get('agent_name', 'unknown'),
        "input_tok":  data.get('input_tokens', 0),
        "output_tok": data.get('output_tokens', 0),
    })
    json.dump(costs, open(COST_FILE, 'w'), indent=2)
    print(json.dumps({"continue": True}))
except Exception:
    print(json.dumps({"continue": True}))
